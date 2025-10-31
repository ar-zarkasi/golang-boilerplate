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
	Authorize(Username string, Password string) (types.UserAuth, int, error)
	RefreshToken(UserID string, RefreshToken string) (types.UserAuth, int, error)
	RegisterUser(userRequest types.RegisterUserRequest) (models.User, int, error)
	RevokeAuthorization(Token string) error
	ListRoles(req types.PagingCursor) ([]types.ListDataRoles, error)
	VerifyToken(token string) (models.User, error)
	VerifyRefreshToken(token string) (models.User, error)
}

type authorizationsService struct {
	h                     helpers.HelperInterface
	userRepository        repository.UserRepository
	userSessionRepository repository.UserSessionRepository
	userProfileRepository repository.UserProfileRepository
	roleRepository        repository.RoleRepository
	userRoleRepository    repository.UserRoleRepository
}

func NewAuthorizationService() AuthorizationsService {
	return &authorizationsService{
		h:                     helpers.NewHelpers(),
		userRepository:        repository.NewUserRepository(),
		userSessionRepository: repository.NewUserSessionRepository(),
		userProfileRepository: repository.NewUserProfileRepository(),
		roleRepository:        repository.NewRoleRepository(),
		userRoleRepository:    repository.NewUserRoleRepository(),
	}
}

func (s *authorizationsService) Authorize(Username string, Password string) (types.UserAuth, int, error) {
	var (
		user      models.User
		err       error
		loginUser types.UserAuth
	)

	if strings.Contains(Username, "@") {
		user, err = s.userRepository.GetByEmail(Username)
	} else if matched, _ := regexp.MatchString(`^\+?[0-9]+$`, Username); matched { // check if username is a phone number
		phone := s.h.NormalizePhone(Username)
		user, err = s.userRepository.GetByPhone(phone)
	} else {
		user, err = s.userRepository.GetByUsername(Username)
	}

	if err != nil {
		return types.UserAuth{}, constants.WrongCredential, err
	}

	verifYPassword := s.h.VerifyPassword(user.PasswordHash, Password)
	if !verifYPassword {
		return types.UserAuth{}, constants.WrongCredential, errors.New("invalid credentials")
	}

	token, err := s.h.GenerateSecureToken(constants.DEFAULT_LENGTH_KEY)
	if err != nil {
		return types.UserAuth{}, constants.InternalServerError, err
	}
	refreshToken, err := s.h.GenerateSecureToken(constants.DEFAULT_LENGTH_KEY)
	if err != nil {
		return types.UserAuth{}, constants.InternalServerError, err
	}

	location := s.h.LoadTimeLocale(user.Profile.Timezone)

	expiresAt := time.Now().In(location).Add(24 * time.Hour) // 24 hours in user's timezone

	session := models.UserSession{
		UserID:       user.ID,
		SessionToken: token,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	session, err = s.userSessionRepository.Create(session)
	if err != nil {
		return types.UserAuth{}, constants.InternalServerError, fmt.Errorf("failed to create session: %w", err)
	}

	loginUser.UserID = user.ID
	loginUser.Username = user.Username
	loginUser.AccessToken = session.SessionToken
	loginUser.RefreshToken = session.RefreshToken
	loginUser.ExpireDate = expiresAt.String()
	loginUser.Scope = &map[string]any{}

	return loginUser, constants.Success, nil
}

func (s *authorizationsService) RefreshToken(UserID string, RefreshToken string) (types.UserAuth, int, error) {
	var (
		user      models.User
		err       error
		loginUser types.UserAuth
	)

	user, err = s.userRepository.GetByID(UserID)
	if err != nil {
		return types.UserAuth{}, constants.Unauthorized, err
	}
	session, err := s.userSessionRepository.GetByRefreshToken(RefreshToken)
	if err != nil {
		return types.UserAuth{}, constants.Unauthorized, err
	}

	if session.UserID != user.ID {
		return types.UserAuth{}, constants.ValidationError, errors.New("invalid session")
	}

	location := s.h.LoadTimeLocale(user.Profile.Timezone)
	token, err := s.h.GenerateSecureToken(constants.DEFAULT_LENGTH_KEY)
	if err != nil {
		return types.UserAuth{}, constants.InternalServerError, err
	}
	refreshToken, err := s.h.GenerateSecureToken(constants.DEFAULT_LENGTH_KEY)
	if err != nil {
		return types.UserAuth{}, constants.InternalServerError, err
	}
	expiresAt := time.Now().In(location).Add(24 * time.Hour) // 24 hours in user's timezone
	newSession := models.UserSession{
		UserID:       user.ID,
		SessionToken: token,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	err = s.userSessionRepository.Delete(session.ID)
	if err != nil {
		return types.UserAuth{}, constants.InternalServerError, fmt.Errorf("failed to delete old session: %w", err)
	}

	newSession, err = s.userSessionRepository.Create(newSession)
	if err != nil {
		return types.UserAuth{}, constants.InternalServerError, fmt.Errorf("failed to create new session: %w", err)
	}

	loginUser.UserID = user.ID
	loginUser.Username = user.Username
	loginUser.AccessToken = newSession.SessionToken
	loginUser.RefreshToken = newSession.RefreshToken
	loginUser.ExpireDate = expiresAt.String()
	loginUser.Scope = &map[string]any{}

	return loginUser, constants.Success, nil
}
func (s *authorizationsService) RegisterUser(userRequest types.RegisterUserRequest) (models.User, int, error) {
	var (
		userNew     models.User
		userProfile models.UserProfile
		userRole    models.UserRole
	)
	if userRequest.Username != nil {
		checkUsername, err := s.userRepository.GetByUsername(*userRequest.Username)
		if err == nil && checkUsername.ID != "" {
			return userNew, constants.ValidationError, fmt.Errorf("username %s already registered", *userRequest.Username)
		}
		userNew.Username = *userRequest.Username
	}

	if userRequest.Email != "" {
		userRequest.Email = strings.ToLower(userRequest.Email)
		checkEmail, err := s.userRepository.GetByEmail(userRequest.Email)
		if err == nil && checkEmail.ID != "" {
			return userNew, constants.ValidationError, fmt.Errorf("email %s already registered", userRequest.Email)
		}
		userNew.Email = userRequest.Email
		if userNew.Username == "" {
			userNew.Username = strings.Split(userRequest.Email, "@")[0] // use email prefix as username if not provided
		}
	} else if userRequest.Phone != "" {
		userRequest.Phone = s.h.NormalizePhone(userRequest.Phone)
		checkPhone, err := s.userRepository.GetByPhone(userRequest.Phone)
		if err == nil && checkPhone.ID != "" {
			return userNew, constants.ValidationError, fmt.Errorf("phone %s already registered", userRequest.Phone)
		}
		if userNew.Username == "" {
			userNew.Username = userRequest.Phone // use phone as username if not provided
		}
	}

	PasswordHash, err := s.h.HashPassword(userRequest.Password)
	if err != nil {
		return userNew, constants.InternalServerError, fmt.Errorf("failed to hash password: %w", err)
	}

	tx := s.h.GetDatabase().DB().Begin()

	userNew.PasswordHash = PasswordHash
	userNew.IsActive = true
	userNew.EmailVerified = false
	userNew, err = s.userRepository.Create(userNew)
	if err != nil {
		tx.Rollback()
		return models.User{}, constants.InternalServerError, fmt.Errorf("failed to create user: %w", err)
	}

	userProfile.UserID = userNew.ID
	userProfile.FirstName = strings.Split(userRequest.FullName, " ")[0]
	userProfile.LastName = strings.Join(strings.Split(userRequest.FullName, " ")[1:], " ")
	userProfile.Timezone = s.h.DefaultValue(userRequest.Timezone, "Asia/Jakarta")
	userProfile.Language = s.h.DefaultValue(userRequest.Language, "en")
	userProfile, err = s.userProfileRepository.Create(userProfile)
	if err != nil {
		tx.Rollback()
		return models.User{}, constants.InternalServerError, fmt.Errorf("failed to create user profile: %w", err)
	}

	// set default role to user
	defaultRole, err := s.getSpecificRole("user")
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

	log.Printf("User %s registered successfully with ID %s", userNew.Username, userNew.ID)
	tx.Commit()
	return userNew, constants.SuccessCreate, nil
}
func (s *authorizationsService) RevokeAuthorization(Token string) error {
	session, err := s.userSessionRepository.GetByToken(Token)
	if err != nil {
		return fmt.Errorf("failed to get session by token: %w", err)
	}

	err = s.userSessionRepository.Delete(session.ID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	s.h.SetUserActive(models.User{})
	s.h.SetTokenActive("")
	s.h.SetUserToken("")

	log.Printf("Session with ID %s revoked successfully", session.ID)
	return nil
}
func (s *authorizationsService) ListRoles(req types.PagingCursor) ([]types.ListDataRoles, error) {
	roles, err := s.roleRepository.GetLists(req.LastValue, req.Limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles: %w", err)
	}
	var roleList []types.ListDataRoles
	for _, role := range roles {
		roleList = append(roleList, types.ListDataRoles{
			ID:        role.ID,
			Name:      role.Name,
			CreatedAt: s.h.GetTimeProvider().FormattedDate(role.CreatedAt.String(), constants.FORMAT_DATETIME_MS),
		})
	}
	return roleList, nil
}
func (s *authorizationsService) VerifyToken(token string) (models.User, error) {
	var (
		user models.User
	)
	session, err := s.userSessionRepository.GetByToken(token)
	if err != nil {
		return user, fmt.Errorf("failed to get session by token: %w", err)
	}
	if session.ID == "" {
		return user, fmt.Errorf("session not found for token: %s", token)
	}

	if time.Now().After(session.ExpiresAt) {
		return user, fmt.Errorf("session expired for token: %s", token)
	}

	user = session.User
	return user, nil
}
func (s *authorizationsService) VerifyRefreshToken(token string) (models.User, error) {
	var (
		user models.User
	)
	session, err := s.userSessionRepository.GetByRefreshToken(token)
	if err != nil {
		return user, fmt.Errorf("failed to get session by refresh token: %w", err)
	}
	if session.ID == "" {
		return user, fmt.Errorf("session not found for token: %s", token)
	}

	user = session.User
	return user, nil
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
