package services

import (
	"app/src/constants"
	"app/src/helpers"
	"app/src/models"
	repository "app/src/repositories"
	"app/src/types"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"
)

type AuthorizationsService interface {
	Authorize(Username string, Password string) (*types.UserAuth, int, error)
	Login(user models.User, loginUser *types.UserAuth) error
	ListRoles(req types.PagingCursor, user models.User) ([]types.ListDataRoles, error)
	VerifyToken(token string, sesId *string) (*models.User, error)
	VerifyRefreshToken(token string, sesId *string) (*models.User, error)
	RevokeAuthorization(token string) error
	CreateAdminUser(email string, password string) (models.User, int, error)
	AppHasAdministrator() bool
	ChangePassword(User models.User, req types.ChangePasswordRequest) (int, error)
	AssignRole(RoleId string, UserId string, by *string) (int, error)
	VerifyTokenOutApp(token string, sesID *string) (*models.User, error)
	AddUser(req types.RegisterUserRequest, user *models.User, userRegist *string) (int, error)
}

type authorizationsService struct {
	Helper                helpers.HelperInterface
	userRepository        repository.UserRepository
	userSessionRepository repository.UserSessionRepository
	userProfileRepository repository.UserProfileRepository
	roleRepository        repository.RoleRepository
	userRoleRepository    repository.UserRoleRepository
}

func NewAuthorizationService(hl helpers.HelperInterface) AuthorizationsService {
	db := hl.GetDatabase().DB()
	return &authorizationsService{
		Helper:                hl,
		userRepository:        repository.NewUserRepository(db),
		userSessionRepository: repository.NewUserSessionRepository(db),
		userProfileRepository: repository.NewUserProfileRepository(db),
		roleRepository:        repository.NewRoleRepository(db),
		userRoleRepository:    repository.NewUserRoleRepository(db),
	}
}

func (s *authorizationsService) Login(user models.User, loginUser *types.UserAuth) error {
	cachingData := types.CacheAuth{}
	scopeLogin := map[string]any{}
	location := s.Helper.LoadTimeLocale(user.Profile.Timezone)
	expiresAt := time.Now().In(location).Add(constants.DEFAULT_EXPIRED_AUTH) // 24 hours in user's timezone
	// register initiate session to database
	session := models.UserSession{
		UserID:       user.ID,
		SessionToken: "",
		RefreshToken: "",
		ExpiresAt:    expiresAt,
	}
	err := s.userSessionRepository.Create(&session)
	if err != nil {
		return fmt.Errorf("failed to create user session: %w", err)
	}
	sessionIDEncrypted, err := s.Helper.Encrypt([]byte(session.ID), nil)
	if err != nil {
		return fmt.Errorf("failed to encrypt session ID: %w", err)
	}
	payload := map[string]any{
		"user":      user,
		"sessionID": sessionIDEncrypted,
		"scope":     scopeLogin,
	}

	token, err := s.Helper.GenerateJWTToken(payload, expiresAt)
	if err != nil {
		return err
	}
	refreshToken, err := s.Helper.GenerateSecureToken(constants.DEFAULT_LENGTH_KEY)
	if err != nil {
		return err
	}

	session.SessionToken = sessionIDEncrypted
	session.RefreshToken = refreshToken

	err = s.userSessionRepository.Update(session.ID, &session)
	if err != nil {
		return fmt.Errorf("failed to update user session: %w", err)
	}
	session.User = user // Associate user with session

	loginUser.UserID = user.ID
	loginUser.Username = user.Username
	loginUser.AccessToken = token
	loginUser.RefreshToken = refreshToken
	loginUser.ExpireDate = expiresAt.Format(constants.FORMAT_DATETIME_MS)
	loginUser.Scope = &scopeLogin

	cachingData.Session = session
	cachingData.LongToken = token

	cacheKey := constants.PREFIX_CACHE_LOGIN_USER + session.ID
	ttl := int(time.Until(expiresAt).Seconds())
	s.Helper.SetCache(cacheKey, cachingData, ttl)
	ttl = int(time.Until(expiresAt.Add(constants.DEFAULT_EXPIRED_AUTH)).Seconds()) // double the TTL for refresh token
	s.Helper.SetCache(refreshToken, cachingData.Session, ttl)

	return nil
}

func (s *authorizationsService) Authorize(Username string, Password string) (*types.UserAuth, int, error) {
	var (
		user      models.User
		err       error
		loginUser types.UserAuth
	)

	if strings.Contains(Username, "@") {
		user, err = s.userRepository.GetByEmail(Username)
	} else if matched, _ := regexp.MatchString(`^\+?[0-9]+$`, Username); matched { // check if username is a phone number
		phone := s.Helper.NormalizePhone(Username)
		user, err = s.userRepository.GetByPhone(phone)
	} else {
		user, err = s.userRepository.GetByUsername(Username)
	}

	if err != nil {
		return nil, constants.ValidationError, err
	}

	verifYPassword := s.Helper.VerifyPassword(user.PasswordHash, Password)
	if !verifYPassword {
		return nil, constants.ValidationError, errors.New("invalid credentials")
	}

	alreadyLogin, _ := s.userSessionRepository.GetByUserID(user.ID)
	loginSession := models.UserSession{}
	for _, session := range alreadyLogin {
		loginSession = session
		break
	}
	if loginSession.ID != "" {
		cacheKey := constants.PREFIX_CACHE_LOGIN_USER + loginSession.ID
		data, err := s.Helper.GetCache(cacheKey)
		if err != nil {
			log.Printf("failed to get cached session: %s", err)
		}
		if data != nil {
			var cachedSession types.CacheAuth
			err = s.Helper.JSONToStruct([]byte(*data), &cachedSession)
			if err != nil {
				return nil, constants.InternalServerError, fmt.Errorf("failed to parse cached session data: %w", err)
			}
			session := models.UserSession{}
			err = s.Helper.InterfaceToStruct(cachedSession.Session, &session)
			if err != nil {
				return nil, constants.InternalServerError, fmt.Errorf("failed to parse cached session data: %w", err)
			}
			user = session.User
			loginUser.AccessToken = cachedSession.LongToken
			loginUser.UserID = user.ID
			loginUser.Username = user.Username
			loginUser.RefreshToken = session.RefreshToken
			loginUser.ExpireDate = session.ExpiresAt.Format(constants.FORMAT_DATETIME_MS)
			loginUser.Scope = &map[string]any{}
			return &loginUser, constants.Success, nil
		}
		// remove old session
		s.RevokeAuthorization(loginSession.ID)
	}

	err = s.Login(user, &loginUser)
	if err != nil {
		log.Println(err)
		return nil, constants.InternalServerError, fmt.Errorf("failed to login user: %w", err)
	}

	return &loginUser, constants.Success, err
}

func (s *authorizationsService) VerifyToken(token string, sesID *string) (*models.User, error) {
	var (
		user models.User
	)

	splitToken := strings.Split(token, ".")
	if len(splitToken) != 3 {
		msg := "invalid token format"
		log.Println(msg)
		return nil, errors.New(msg)
	}

	payload := map[string]any{}
	err := s.Helper.ParsingJWT(token, &payload)
	if err != nil {
		log.Println(err)
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	sessionIDEncrypted := payload["sessionID"].(string)

	sessionID, err := s.Helper.Decrypt(sessionIDEncrypted, nil)
	if err != nil {
		log.Println(err)
		return nil, fmt.Errorf("failed to decrypt session ID: %w", err)
	}

	sessionIDString := string(sessionID)
	*sesID = sessionIDString

	cachedData, err := s.Helper.GetCache(*sesID)
	if err == nil {
		var cachedSession types.CacheAuth
		err = s.Helper.JSONToStruct([]byte(*cachedData), &cachedSession)
		if err != nil {
			log.Println(err)
			return nil, fmt.Errorf("failed to parse cached session data: %w", err)
		}
		session := models.UserSession{}
		err = s.Helper.InterfaceToStruct(cachedSession.Session, &session)
		if err != nil {
			log.Println(err)
			return nil, fmt.Errorf("failed to parse cached session data: %w", err)
		}
		user = session.User
		return &user, nil
	}

	session, err := s.userSessionRepository.GetByID(string(sessionID))
	if err != nil {
		log.Println(err)
		return nil, fmt.Errorf("session not found: %w", err)
	}

	user = session.User
	// set new cache
	cachingData := types.CacheAuth{
		Session:   session,
		LongToken: token,
	}
	cacheKey := constants.PREFIX_CACHE_LOGIN_USER + session.ID
	ttl := int(time.Until(session.ExpiresAt).Seconds())
	err = s.Helper.SetCache(cacheKey, cachingData, ttl)
	if err != nil {
		log.Println(err)
		return nil, fmt.Errorf("failed to set cache: %w", err)
	}

	return &user, nil

}

func (s *authorizationsService) VerifyRefreshToken(token string, sesID *string) (*models.User, error) {
	var (
		user    models.User
		session models.UserSession
	)

	cachedData, err := s.Helper.GetCache(token)
	if err == nil && cachedData != nil {
		err = s.Helper.JSONToStruct([]byte(*cachedData), &session)
		if err != nil {
			log.Println(err)
			return nil, fmt.Errorf("failed to parse cached refresh data: %w", err)
		}

		user = session.User
		*sesID = session.ID
		return &user, nil
	}

	session, err = s.userSessionRepository.GetByRefreshToken(token)
	if err != nil {
		log.Println(err)
		return nil, fmt.Errorf("session not found: %w", err)
	}

	user = session.User
	*sesID = session.ID
	// set new cache
	ttl := int(time.Until(session.ExpiresAt).Seconds())
	err = s.Helper.SetCache(token, session, ttl)
	if err != nil {
		log.Println(err)
		return nil, fmt.Errorf("failed to set cache: %w", err)
	}

	return &user, nil
}

func (s *authorizationsService) RevokeAuthorization(sessionID string) error {
	session, err := s.userSessionRepository.GetByID(sessionID)
	if err != nil {
		log.Printf("Failed to get session: %v", err)
		return fmt.Errorf("failed authorization")
	}

	keyCache := constants.PREFIX_CACHE_LOGIN_USER + sessionID
	_ = s.Helper.DeleteCache(keyCache)

	refreshToken := session.RefreshToken
	_ = s.Helper.DeleteCache(refreshToken)

	err = s.userSessionRepository.Delete(session.ID, session)
	if err != nil {
		log.Printf("Failed to delete session: %v", err)
		return fmt.Errorf("failed to delete session: %w", err)
	}

	log.Printf("Session with ID %s has been revoked successfully", session.ID)
	return nil

}

func (s *authorizationsService) ListRoles(req types.PagingCursor, user models.User) ([]types.ListDataRoles, error) {
	var (
		filters      []types.FilterQuery
		adminRole    string        = constants.DEFAULT_ADMIN_ROLE
		defaultSort  string        = "created_at"
		defaultOrder types.SORTING = types.SORTING_DESC
	)
	log.Println(req)
	if req.QueryString != nil {
		filters = req.QueryString
	}
	if req.SortBy == nil {
		req.SortBy = &defaultSort
	}
	if req.SortOrder == nil {
		req.SortOrder = &defaultOrder
	}

	isAdmin := s.checkUserHasRole(adminRole, user)
	if !isAdmin {
		temp := types.FilterQuery{
			Column:  "name",
			Operand: "!=",
			Value:   &adminRole,
		}
		filters = append(filters, temp)
	}
	roles, err := s.roleRepository.GetListsCursor(filters, req.LastValue, *req.SortBy, *req.SortOrder, req.Limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles: %w", err)
	}
	var roleList []types.ListDataRoles
	for _, role := range roles {
		roleList = append(roleList, types.ListDataRoles{
			RoleID:    role.ID,
			Name:      role.Name,
			CreatedAt: role.CreatedAt.Format(constants.FORMAT_DATETIME_MS),
		})
	}
	return roleList, nil
}
func (s *authorizationsService) getSpecificRole(roleName string) (*models.Role, error) {
	role, err := s.roleRepository.GetByName(roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to get role by name: %w", err)
	}

	if role.ID == "" {
		return nil, fmt.Errorf("role not found: %s", roleName)
	}

	return &role, nil
}
func (s *authorizationsService) checkUserHasRole(roleName string, user models.User) bool {
	role, err := s.getSpecificRole(roleName)
	if err != nil {
		log.Printf("Error getting role %s: %v", roleName, err)
		return false
	}
	exists, err := s.userRoleRepository.CheckUserRole(user.ID, role.ID)
	if err != nil {
		log.Println(err)
		return false
	}
	return exists
}

func (s *authorizationsService) CreateAdminUser(email string, password string) (models.User, int, error) {
	var (
		userNew     models.User
		userProfile models.UserProfile
		userRole    models.UserRole
	)
	name := strings.Split(email, "@")[0]
	defaultTimeZone := constants.DEFAULT_TIMEZONE
	defaultLang := constants.DEFAULT_LOCALE
	userRequest := types.RegisterUserRequest{
		Username: &email,
		Email:    email,
		Password: password,
		FullName: name,
		Timezone: &defaultTimeZone,
		Language: &defaultLang,
	}

	PasswordHash, err := s.Helper.HashPassword(userRequest.Password)
	if err != nil {
		return userNew, constants.InternalServerError, fmt.Errorf("failed to hash password: %w", err)
	}

	tx := s.Helper.GetDatabase().DB().Begin()

	userNew.Username = *userRequest.Username
	userNew.Email = userRequest.Email
	userNew.PasswordHash = PasswordHash
	userNew.IsActive = true
	userNew.EmailVerified = true
	err = s.userRepository.Create(&userNew)
	if err != nil {
		tx.Rollback()
		return models.User{}, constants.InternalServerError, fmt.Errorf("failed to create user: %w", err)
	}

	userProfile.UserID = userNew.ID
	userProfile.FirstName = strings.Split(userRequest.FullName, " ")[0]
	userProfile.LastName = strings.Join(strings.Split(userRequest.FullName, " ")[1:], " ")
	userProfile.Timezone = s.Helper.DefaultValue(userRequest.Timezone, "Asia/Jakarta")
	userProfile.Language = s.Helper.DefaultValue(userRequest.Language, "en")
	err = s.userProfileRepository.Create(&userProfile)
	if err != nil {
		tx.Rollback()
		return models.User{}, constants.InternalServerError, fmt.Errorf("failed to create user profile: %w", err)
	}

	// set default role to user
	defaultRole, err := s.getSpecificRole("admin")
	if err != nil {
		return models.User{}, constants.InternalServerError, fmt.Errorf("failed to get default role: %w", err)
	}
	userRole.UserID = userNew.ID
	userRole.RoleID = defaultRole.ID
	userRole.AssignedAt = time.Now()
	err = s.userRoleRepository.AssignRole(userRole)
	if err != nil {
		tx.Rollback()
		return models.User{}, constants.InternalServerError, fmt.Errorf("failed to assign role to user: %w", err)
	}

	log.Printf("User admin %s registered successfully with ID %s", userNew.Username, userNew.ID)
	tx.Commit()
	return userNew, constants.SuccessCreate, nil
}

func (s *authorizationsService) AppHasAdministrator() bool {
	adminRole, err := s.roleRepository.GetByName("admin")
	if err != nil {
		log.Printf("Error checking admin role: %v", err)
		return false
	}

	hit := s.userRepository.CountRoleActiveUsers(adminRole.ID)
	return hit > 0
}

func (s *authorizationsService) ChangePassword(User models.User, req types.ChangePasswordRequest) (int, error) {
	log.Printf("the Has Password is %s \n", User.ID)
	if !s.Helper.VerifyPassword(User.PasswordHash, req.CurrentPassword) {
		return constants.ValidationError, errors.New("wrong current password")
	}
	newPasswordHash, err := s.Helper.HashPassword(req.NewPassword)
	if err != nil {
		return constants.InternalServerError, fmt.Errorf("failed to hash new password: %w", err)
	}

	tx := s.Helper.GetDatabase().DB().Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			log.Printf("Recovered from panic: %v", r)
		}
	}()

	User.PasswordHash = newPasswordHash
	err = s.userRepository.Update(User.ID, &User)
	if err != nil {
		return constants.InternalServerError, fmt.Errorf("failed to update user password: %w", err)
	}

	allSessionLogged, err := s.userSessionRepository.GetByUserID(User.ID)
	if err != nil {
		log.Printf("Failed to get user sessions: %v", err)
		return constants.InternalServerError, fmt.Errorf("failed to get user sessions: %w", err)
	}
	for _, session := range allSessionLogged {
		s.RevokeAuthorization(session.ID)
	}

	tx.Commit()
	return constants.Success, nil
}

func (s *authorizationsService) AssignRole(RoleId string, UserId string, by *string) (int, error) {
	check, _ := s.userRoleRepository.CheckUserRole(UserId, RoleId)
	if check {
		return constants.ValidationError, fmt.Errorf("user already using that role")
	}

	role, err := s.roleRepository.GetByID(RoleId)
	if err != nil {
		return constants.InternalServerError, fmt.Errorf("failed to get role by ID: %w", err)
	}

	user, err := s.userRepository.GetByID(UserId)
	if err != nil {
		return constants.InternalServerError, fmt.Errorf("failed to get user by ID: %w", err)
	}

	userRole := models.UserRole{
		UserID:     user.ID,
		RoleID:     role.ID,
		AssignedAt: time.Now(),
		AssignedBy: by,
	}

	err = s.userRoleRepository.AssignRole(userRole)
	if err != nil {
		return constants.InternalServerError, fmt.Errorf("failed to assign role to user: %w", err)
	}

	log.Printf("User %s has been assigned role %s successfully", user.Username, role.Name)
	return constants.Success, nil
}

// Use as middleware outside auth app
func (s *authorizationsService) VerifyTokenOutApp(token string, sesID *string) (*models.User, error) {
	var (
		user models.User
	)

	splitToken := strings.Split(token, ".")
	if len(splitToken) != 3 {
		msg := "invalid token format"
		log.Println(msg)
		return nil, errors.New(msg)
	}

	payload := map[string]any{}
	err := s.Helper.ParsingJWT(token, &payload)
	if err != nil {
		log.Println(err)
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if payload["sessionID"] == nil {
		log.Println("Session ID not found on token")
		return nil, errors.New("not authorized")
	}

	sessionIDEncrypted := payload["sessionID"].(string)

	sessionID, err := s.Helper.Decrypt(sessionIDEncrypted, nil)
	if err != nil {
		log.Println(err)
		return nil, fmt.Errorf("failed to decrypt session ID: %w", err)
	}

	sessionIDString := string(sessionID)
	*sesID = sessionIDString
	keyCache := constants.PREFIX_CACHE_LOGIN_USER + *sesID
	cachedData, err := s.Helper.GetCache(keyCache)
	if err == nil {
		var cachedSession types.CacheAuth
		err = s.Helper.JSONToStruct([]byte(*cachedData), &cachedSession)
		if err != nil {
			log.Println(err)
			return nil, fmt.Errorf("failed to parse cached session data: %w", err)
		}
		session := models.UserSession{}
		err = s.Helper.InterfaceToStruct(cachedSession.Session, &session)
		if err != nil {
			log.Println(err)
			return nil, fmt.Errorf("failed to parse cached session data: %w", err)
		}
		user = session.User
		return &user, nil
	}
	log.Println(err, cachedData)
	return nil, errors.New("not authorized")

}

func (s *authorizationsService) AddUser(req types.RegisterUserRequest, user *models.User, userRegist *string) (int, error) {
	PasswordHash, err := s.Helper.HashPassword(req.Password)
	if err != nil {
		log.Println(err)
		return constants.InternalServerError, fmt.Errorf("failed to hash password: %w", err)
	}

	tx := s.Helper.GetDatabase().DB().Begin()

	usern := req.Email
	if req.Username != nil {
		usern = *req.Username
	}
	user.Username = usern
	user.Email = req.Email
	user.Phone = req.Phone
	user.PasswordHash = PasswordHash
	user.IsActive = true
	user.EmailVerified = true
	err = s.userRepository.Create(user)
	if err != nil {
		tx.Rollback()
		return constants.InternalServerError, fmt.Errorf("failed to create user: %w", err)
	}

	userProfile := models.UserProfile{}
	userProfile.UserID = user.ID
	userProfile.FirstName = strings.Split(req.FullName, " ")[0]
	userProfile.LastName = strings.Join(strings.Split(req.FullName, " ")[1:], " ")
	userProfile.Timezone = s.Helper.DefaultValue(req.Timezone, "Asia/Jakarta")
	userProfile.Language = s.Helper.DefaultValue(req.Language, "en")
	err = s.userProfileRepository.Create(&userProfile)
	if err != nil {
		tx.Rollback()
		return constants.InternalServerError, fmt.Errorf("failed to create user profile: %w", err)
	}
	user.Profile = &userProfile

	// set default role to user
	defaultRole, err := s.roleRepository.GetByName(constants.DEFAULT_USER_ROLE)
	if err != nil {
		return constants.InternalServerError, fmt.Errorf("role user not exists")
	}
	userRole := models.UserRole{}
	userRole.UserID = user.ID
	userRole.RoleID = defaultRole.ID
	userRole.AssignedAt = time.Now()
	userRole.AssignedBy = userRegist
	err = s.userRoleRepository.AssignRole(userRole)
	if err != nil {
		tx.Rollback()
		return constants.InternalServerError, fmt.Errorf("failed to assign role to user: %w", err)
	}

	log.Printf("User admin %s registered successfully with ID %s", user.Username, user.ID)
	tx.Commit()
	return constants.SuccessCreate, nil
}
