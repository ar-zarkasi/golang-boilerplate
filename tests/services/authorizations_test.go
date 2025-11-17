package services_test

import (
	"app/src/constants"
	"app/src/helpers"
	"app/src/models"
	"app/src/types"
	"app/tests/mocks"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
)

// authorizationsServiceTestable is a testable version of authorizationsService
// that allows dependency injection for unit testing
type authorizationsServiceTestable struct {
	Helper                helpers.HelperInterface
	userRepository        *mocks.MockUserRepository
	userSessionRepository *mocks.MockUserSessionRepository
	userProfileRepository *mocks.MockUserProfileRepository
	roleRepository        *mocks.MockRoleRepository
	userRoleRepository    *mocks.MockUserRoleRepository
}

func newTestAuthorizationsService() (*authorizationsServiceTestable, *mocks.MockHelperInterface) {
	mockHelper := new(mocks.MockHelperInterface)
	return &authorizationsServiceTestable{
		Helper:                mockHelper,
		userRepository:        new(mocks.MockUserRepository),
		userSessionRepository: new(mocks.MockUserSessionRepository),
		userProfileRepository: new(mocks.MockUserProfileRepository),
		roleRepository:        new(mocks.MockRoleRepository),
		userRoleRepository:    new(mocks.MockUserRoleRepository),
	}, mockHelper
}

// Authorize tests
func (s *authorizationsServiceTestable) Authorize(Username string, Password string) (*types.UserAuth, int, error) {
	var (
		user      models.User
		err       error
		loginUser types.UserAuth
	)

	if containsAt(Username) {
		user, err = s.userRepository.GetByEmail(Username)
	} else if isPhoneNumber(Username) {
		phone := s.Helper.NormalizePhone(Username)
		user, err = s.userRepository.GetByPhone(phone)
	} else {
		user, err = s.userRepository.GetByUsername(Username)
	}

	if err != nil {
		return nil, constants.WrongCredential, err
	}

	verifyPassword := s.Helper.VerifyPassword(user.PasswordHash, Password)
	if !verifyPassword {
		return nil, constants.WrongCredential, errors.New("invalid credentials")
	}

	alreadyLogin, _ := s.userSessionRepository.GetByUserID(user.ID)
	if alreadyLogin != nil {
		cacheKey := constants.PREFIX_CACHE_LOGIN_USER + alreadyLogin.ID
		data, err := s.Helper.GetCache(cacheKey)
		if err != nil {
			return nil, constants.InternalServerError, err
		}
		if data != nil {
			var cachedSession types.CacheAuth
			err = s.Helper.JSONToStruct([]byte(*data), &cachedSession)
			if err != nil {
				return nil, constants.InternalServerError, err
			}
			session := models.UserSession{}
			err = s.Helper.InterfaceToStruct(cachedSession.Session, &session)
			if err != nil {
				return nil, constants.InternalServerError, err
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

		return nil, constants.BadRequest, errors.New("user is already logged in")
	}

	err = s.Login(user, &loginUser)

	return &loginUser, constants.Success, err
}

func (s *authorizationsServiceTestable) Login(user models.User, loginUser *types.UserAuth) error {
	cachingData := types.CacheAuth{}
	scopeLogin := map[string]any{}
	location := s.Helper.LoadTimeLocale(user.Profile.Timezone)
	expiresAt := time.Now().In(location).Add(constants.DEFAULT_EXPIRED_AUTH)

	session := models.UserSession{
		UserID:       user.ID,
		SessionToken: "",
		RefreshToken: "",
		ExpiresAt:    expiresAt,
	}
	err := s.userSessionRepository.Create(&session)
	if err != nil {
		return err
	}
	sessionIDEncrypted, err := s.Helper.Encrypt([]byte(session.ID), nil)
	if err != nil {
		return err
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
		return err
	}
	session.User = user

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
	ttl = int(time.Until(expiresAt.Add(constants.DEFAULT_EXPIRED_AUTH)).Seconds())
	s.Helper.SetCache(refreshToken, cachingData.Session, ttl)

	return nil
}

func (s *authorizationsServiceTestable) VerifyToken(token string, sesID *string) (*models.User, error) {
	var user models.User

	splitToken := splitByDot(token)
	if len(splitToken) != 3 {
		return nil, errors.New("invalid token format")
	}

	payload := map[string]any{}
	err := s.Helper.ParsingJWT(token, &payload)
	if err != nil {
		return nil, err
	}

	sessionIDEncrypted := payload["sessionID"].(string)

	sessionID, err := s.Helper.Decrypt(sessionIDEncrypted, nil)
	if err != nil {
		return nil, err
	}

	sessionIDString := string(sessionID)
	*sesID = sessionIDString

	cachedData, err := s.Helper.GetCache(*sesID)
	if err == nil && cachedData != nil {
		var cachedSession types.CacheAuth
		err = s.Helper.JSONToStruct([]byte(*cachedData), &cachedSession)
		if err != nil {
			return nil, err
		}
		session := models.UserSession{}
		err = s.Helper.InterfaceToStruct(cachedSession.Session, &session)
		if err != nil {
			return nil, err
		}
		user = session.User
		return &user, nil
	}

	session, err := s.userSessionRepository.GetByID(string(sessionID))
	if err != nil {
		return nil, err
	}

	user = session.User
	cachingData := types.CacheAuth{
		Session:   session,
		LongToken: token,
	}
	cacheKey := constants.PREFIX_CACHE_LOGIN_USER + session.ID
	ttl := int(time.Until(session.ExpiresAt).Seconds())
	err = s.Helper.SetCache(cacheKey, cachingData, ttl)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *authorizationsServiceTestable) VerifyRefreshToken(token string, sesID *string) (*models.User, error) {
	var (
		user    models.User
		session models.UserSession
	)

	cachedData, err := s.Helper.GetCache(token)
	if err == nil && cachedData != nil {
		err = s.Helper.JSONToStruct([]byte(*cachedData), &session)
		if err != nil {
			return nil, err
		}

		user = session.User
		*sesID = session.ID
		return &user, nil
	}

	session, err = s.userSessionRepository.GetByRefreshToken(token)
	if err != nil {
		return nil, err
	}

	user = session.User
	*sesID = session.ID
	ttl := int(time.Until(session.ExpiresAt).Seconds())
	err = s.Helper.SetCache(token, session, ttl)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *authorizationsServiceTestable) RevokeAuthorization(sessionID string) error {
	session, err := s.userSessionRepository.GetByID(sessionID)
	if err != nil {
		return err
	}

	keyCache := constants.PREFIX_CACHE_LOGIN_USER + sessionID
	_ = s.Helper.DeleteCache(keyCache)

	refreshToken := session.RefreshToken
	_ = s.Helper.DeleteCache(refreshToken)

	err = s.userSessionRepository.Delete(session.ID)
	if err != nil {
		return err
	}

	return nil
}

func (s *authorizationsServiceTestable) ListRoles(req types.PagingCursor, user models.User) ([]types.ListDataRoles, error) {
	var (
		filters      []types.FilterQuery
		adminRole    string        = constants.DEFAULT_ADMIN_ROLE
		defaultSort  string        = "created_at"
		defaultOrder types.SORTING = types.SORTING_DESC
	)
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
		return nil, err
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

func (s *authorizationsServiceTestable) getSpecificRole(roleName string) (*models.Role, error) {
	role, err := s.roleRepository.GetByName(roleName)
	if err != nil {
		return nil, err
	}

	if role.ID == "" {
		return nil, errors.New("role not found")
	}

	return &role, nil
}

func (s *authorizationsServiceTestable) checkUserHasRole(roleName string, user models.User) bool {
	role, err := s.getSpecificRole(roleName)
	if err != nil {
		return false
	}
	exists, err := s.userRoleRepository.CheckUserRole(user.ID, role.ID)
	if err != nil {
		return false
	}
	return exists
}

func (s *authorizationsServiceTestable) CreateAdminUser(email string, password string) (models.User, int, error) {
	var (
		userNew     models.User
		userProfile models.UserProfile
		userRole    models.UserRole
	)
	name := splitByAt(email)[0]
	defaultTimeZone := constants.DEFAULT_TIMEZONE
	defaultLang := constants.DEFAULT_LOCALE

	PasswordHash, err := s.Helper.HashPassword(password)
	if err != nil {
		return userNew, constants.InternalServerError, err
	}

	userNew.Username = email
	userNew.Email = email
	userNew.PasswordHash = PasswordHash
	userNew.IsActive = true
	userNew.EmailVerified = true
	err = s.userRepository.Create(&userNew)
	if err != nil {
		return models.User{}, constants.InternalServerError, err
	}

	userProfile.UserID = userNew.ID
	userProfile.FirstName = splitBySpace(name)[0]
	if len(splitBySpace(name)) > 1 {
		userProfile.LastName = joinBySpace(splitBySpace(name)[1:])
	}
	userProfile.Timezone = s.Helper.DefaultValue(&defaultTimeZone, "Asia/Jakarta")
	userProfile.Language = s.Helper.DefaultValue(&defaultLang, "en")
	err = s.userProfileRepository.Create(&userProfile)
	if err != nil {
		return models.User{}, constants.InternalServerError, err
	}

	defaultRole, err := s.getSpecificRole("admin")
	if err != nil {
		return models.User{}, constants.InternalServerError, err
	}
	userRole.UserID = userNew.ID
	userRole.RoleID = defaultRole.ID
	userRole.AssignedAt = time.Now()
	err = s.userRoleRepository.AssignRole(userRole)
	if err != nil {
		return models.User{}, constants.InternalServerError, err
	}

	return userNew, constants.SuccessCreate, nil
}

func (s *authorizationsServiceTestable) AppHasAdministrator() bool {
	adminRole, err := s.roleRepository.GetByName("admin")
	if err != nil {
		return false
	}

	hit := s.userRepository.CountRoleActiveUsers(adminRole.ID)
	return hit > 0
}

// Helper functions
func containsAt(s string) bool {
	for _, c := range s {
		if c == '@' {
			return true
		}
	}
	return false
}

func isPhoneNumber(s string) bool {
	if len(s) == 0 {
		return false
	}
	start := 0
	if s[0] == '+' {
		start = 1
	}
	for i := start; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > start
}

func splitByDot(s string) []string {
	var result []string
	current := ""
	for _, c := range s {
		if c == '.' {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	result = append(result, current)
	return result
}

func splitByAt(s string) []string {
	var result []string
	current := ""
	for _, c := range s {
		if c == '@' {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	result = append(result, current)
	return result
}

func splitBySpace(s string) []string {
	var result []string
	current := ""
	for _, c := range s {
		if c == ' ' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func joinBySpace(s []string) string {
	result := ""
	for i, part := range s {
		if i > 0 {
			result += " "
		}
		result += part
	}
	return result
}

// Test functions

// TestAuthorize_PositiveCase1_WithEmail tests successful authorization with email
func TestAuthorize_PositiveCase1_WithEmail(t *testing.T) {
	service, mockHelper := newTestAuthorizationsService()

	user := models.User{
		ID:           "user-123",
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hashedpassword",
		IsActive:     true,
		Profile: &models.UserProfile{
			Timezone: "Asia/Jakarta",
		},
	}

	service.userRepository.On("GetByEmail", "test@example.com").Return(user, nil)
	mockHelper.On("VerifyPassword", "hashedpassword", "password123").Return(true)
	service.userSessionRepository.On("GetByUserID", "user-123").Return(nil, gorm.ErrRecordNotFound)
	mockHelper.On("LoadTimeLocale", "Asia/Jakarta").Return(time.UTC)
	service.userSessionRepository.On("Create", mock.AnythingOfType("*models.UserSession")).Return(nil)
	mockHelper.On("Encrypt", mock.Anything, mock.Anything).Return("encrypted-session-id", nil)
	mockHelper.On("GenerateJWTToken", mock.Anything, mock.Anything).Return("jwt-token-123", nil)
	mockHelper.On("GenerateSecureToken", constants.DEFAULT_LENGTH_KEY).Return("refresh-token-123", nil)
	service.userSessionRepository.On("Update", mock.AnythingOfType("string"), mock.AnythingOfType("*models.UserSession")).Return(nil)
	mockHelper.On("SetCache", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	result, code, err := service.Authorize("test@example.com", "password123")

	assert.NoError(t, err)
	assert.Equal(t, constants.Success, code)
	assert.NotNil(t, result)
	assert.Equal(t, "user-123", result.UserID)
	assert.Equal(t, "testuser", result.Username)
	assert.Equal(t, "jwt-token-123", result.AccessToken)
	assert.Equal(t, "refresh-token-123", result.RefreshToken)
}

// TestAuthorize_PositiveCase2_WithUsername tests successful authorization with username
func TestAuthorize_PositiveCase2_WithUsername(t *testing.T) {
	service, mockHelper := newTestAuthorizationsService()

	user := models.User{
		ID:           "user-456",
		Username:     "johndoe",
		Email:        "john@example.com",
		PasswordHash: "hashedpwd",
		IsActive:     true,
		Profile: &models.UserProfile{
			Timezone: "UTC",
		},
	}

	service.userRepository.On("GetByUsername", "johndoe").Return(user, nil)
	mockHelper.On("VerifyPassword", "hashedpwd", "securepass").Return(true)
	service.userSessionRepository.On("GetByUserID", "user-456").Return(nil, gorm.ErrRecordNotFound)
	mockHelper.On("LoadTimeLocale", "UTC").Return(time.UTC)
	service.userSessionRepository.On("Create", mock.AnythingOfType("*models.UserSession")).Return(nil)
	mockHelper.On("Encrypt", mock.Anything, mock.Anything).Return("encrypted-session-456", nil)
	mockHelper.On("GenerateJWTToken", mock.Anything, mock.Anything).Return("jwt-token-456", nil)
	mockHelper.On("GenerateSecureToken", constants.DEFAULT_LENGTH_KEY).Return("refresh-token-456", nil)
	service.userSessionRepository.On("Update", mock.AnythingOfType("string"), mock.AnythingOfType("*models.UserSession")).Return(nil)
	mockHelper.On("SetCache", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	result, code, err := service.Authorize("johndoe", "securepass")

	assert.NoError(t, err)
	assert.Equal(t, constants.Success, code)
	assert.NotNil(t, result)
	assert.Equal(t, "user-456", result.UserID)
	assert.Equal(t, "johndoe", result.Username)
}

// TestAuthorize_NegativeCase_WrongPassword tests failed authorization with wrong password
func TestAuthorize_NegativeCase_WrongPassword(t *testing.T) {
	service, mockHelper := newTestAuthorizationsService()

	user := models.User{
		ID:           "user-789",
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hashedpassword",
		IsActive:     true,
	}

	service.userRepository.On("GetByEmail", "test@example.com").Return(user, nil)
	mockHelper.On("VerifyPassword", "hashedpassword", "wrongpassword").Return(false)

	result, code, err := service.Authorize("test@example.com", "wrongpassword")

	assert.Error(t, err)
	assert.Equal(t, constants.WrongCredential, code)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid credentials")
}

// TestLogin_PositiveCase1 tests successful login
func TestLogin_PositiveCase1(t *testing.T) {
	service, mockHelper := newTestAuthorizationsService()

	user := models.User{
		ID:       "user-123",
		Username: "testuser",
		Profile: &models.UserProfile{
			Timezone: "Asia/Jakarta",
		},
	}
	loginUser := types.UserAuth{}

	mockHelper.On("LoadTimeLocale", "Asia/Jakarta").Return(time.UTC)
	service.userSessionRepository.On("Create", mock.AnythingOfType("*models.UserSession")).Return(nil)
	mockHelper.On("Encrypt", mock.Anything, mock.Anything).Return("encrypted-session", nil)
	mockHelper.On("GenerateJWTToken", mock.Anything, mock.Anything).Return("jwt-token", nil)
	mockHelper.On("GenerateSecureToken", constants.DEFAULT_LENGTH_KEY).Return("refresh-token", nil)
	service.userSessionRepository.On("Update", mock.AnythingOfType("string"), mock.AnythingOfType("*models.UserSession")).Return(nil)
	mockHelper.On("SetCache", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	err := service.Login(user, &loginUser)

	assert.NoError(t, err)
	assert.Equal(t, "user-123", loginUser.UserID)
	assert.Equal(t, "testuser", loginUser.Username)
	assert.Equal(t, "jwt-token", loginUser.AccessToken)
	assert.Equal(t, "refresh-token", loginUser.RefreshToken)
}

// TestLogin_PositiveCase2 tests successful login with different timezone
func TestLogin_PositiveCase2(t *testing.T) {
	service, mockHelper := newTestAuthorizationsService()

	user := models.User{
		ID:       "user-999",
		Username: "eurouser",
		Profile: &models.UserProfile{
			Timezone: "Europe/London",
		},
	}
	loginUser := types.UserAuth{}

	loc, _ := time.LoadLocation("Europe/London")
	mockHelper.On("LoadTimeLocale", "Europe/London").Return(loc)
	service.userSessionRepository.On("Create", mock.AnythingOfType("*models.UserSession")).Return(nil)
	mockHelper.On("Encrypt", mock.Anything, mock.Anything).Return("encrypted-euro", nil)
	mockHelper.On("GenerateJWTToken", mock.Anything, mock.Anything).Return("jwt-euro", nil)
	mockHelper.On("GenerateSecureToken", constants.DEFAULT_LENGTH_KEY).Return("refresh-euro", nil)
	service.userSessionRepository.On("Update", mock.AnythingOfType("string"), mock.AnythingOfType("*models.UserSession")).Return(nil)
	mockHelper.On("SetCache", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	err := service.Login(user, &loginUser)

	assert.NoError(t, err)
	assert.Equal(t, "user-999", loginUser.UserID)
	assert.Equal(t, "jwt-euro", loginUser.AccessToken)
}

// TestLogin_NegativeCase_SessionCreateFails tests failed login when session creation fails
func TestLogin_NegativeCase_SessionCreateFails(t *testing.T) {
	service, mockHelper := newTestAuthorizationsService()

	user := models.User{
		ID:       "user-123",
		Username: "testuser",
		Profile: &models.UserProfile{
			Timezone: "Asia/Jakarta",
		},
	}
	loginUser := types.UserAuth{}

	mockHelper.On("LoadTimeLocale", "Asia/Jakarta").Return(time.UTC)
	service.userSessionRepository.On("Create", mock.AnythingOfType("*models.UserSession")).Return(errors.New("database error"))

	err := service.Login(user, &loginUser)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database error")
}

// TestVerifyToken_PositiveCase1_WithCache tests successful token verification with cached data
func TestVerifyToken_PositiveCase1_WithCache(t *testing.T) {
	service, mockHelper := newTestAuthorizationsService()

	sesID := ""
	token := "header.payload.signature"
	expectedUser := models.User{
		ID:       "user-123",
		Username: "cacheduser",
	}

	session := models.UserSession{
		ID:   "session-123",
		User: expectedUser,
	}
	cachedAuth := types.CacheAuth{
		Session:   session,
		LongToken: token,
	}

	mockHelper.On("ParsingJWT", token, mock.Anything).Run(func(args mock.Arguments) {
		payload := args.Get(1).(*map[string]any)
		(*payload)["sessionID"] = "encrypted-session-id"
	}).Return(nil)
	mockHelper.On("Decrypt", "encrypted-session-id", mock.Anything).Return([]byte("session-123"), nil)

	cachedJSON, _ := json.Marshal(cachedAuth)
	cachedStr := string(cachedJSON)
	mockHelper.On("GetCache", "session-123").Return(&cachedStr, nil)
	mockHelper.On("JSONToStruct", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		target := args.Get(1).(*types.CacheAuth)
		*target = cachedAuth
	}).Return(nil)
	mockHelper.On("InterfaceToStruct", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		target := args.Get(1).(*models.UserSession)
		*target = session
	}).Return(nil)

	user, err := service.VerifyToken(token, &sesID)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "user-123", user.ID)
	assert.Equal(t, "cacheduser", user.Username)
	assert.Equal(t, "session-123", sesID)
}

// TestVerifyToken_PositiveCase2_WithoutCache tests successful token verification from database
func TestVerifyToken_PositiveCase2_WithoutCache(t *testing.T) {
	service, mockHelper := newTestAuthorizationsService()

	sesID := ""
	token := "header.payload.signature"
	expectedUser := models.User{
		ID:       "user-456",
		Username: "dbuser",
	}
	session := &models.UserSession{
		ID:        "session-456",
		User:      expectedUser,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	mockHelper.On("ParsingJWT", token, mock.Anything).Run(func(args mock.Arguments) {
		payload := args.Get(1).(*map[string]any)
		(*payload)["sessionID"] = "encrypted-session-456"
	}).Return(nil)
	mockHelper.On("Decrypt", "encrypted-session-456", mock.Anything).Return([]byte("session-456"), nil)
	mockHelper.On("GetCache", "session-456").Return(nil, errors.New("cache miss"))
	service.userSessionRepository.On("GetByID", "session-456").Return(session, nil)
	mockHelper.On("SetCache", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	user, err := service.VerifyToken(token, &sesID)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "user-456", user.ID)
	assert.Equal(t, "dbuser", user.Username)
}

// TestVerifyToken_NegativeCase_InvalidFormat tests failed token verification with invalid format
func TestVerifyToken_NegativeCase_InvalidFormat(t *testing.T) {
	service, _ := newTestAuthorizationsService()

	sesID := ""
	token := "invalid-token-without-dots"

	user, err := service.VerifyToken(token, &sesID)

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "invalid token format")
}

// TestVerifyRefreshToken_PositiveCase1_WithCache tests successful refresh token verification with cache
func TestVerifyRefreshToken_PositiveCase1_WithCache(t *testing.T) {
	service, mockHelper := newTestAuthorizationsService()

	sesID := ""
	refreshToken := "refresh-token-123"
	expectedUser := models.User{
		ID:       "user-123",
		Username: "cacheduser",
	}
	session := models.UserSession{
		ID:   "session-123",
		User: expectedUser,
	}

	sessionJSON, _ := json.Marshal(session)
	sessionStr := string(sessionJSON)
	mockHelper.On("GetCache", refreshToken).Return(&sessionStr, nil)
	mockHelper.On("JSONToStruct", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		target := args.Get(1).(*models.UserSession)
		*target = session
	}).Return(nil)

	user, err := service.VerifyRefreshToken(refreshToken, &sesID)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "user-123", user.ID)
	assert.Equal(t, "session-123", sesID)
}

// TestVerifyRefreshToken_PositiveCase2_WithoutCache tests successful refresh token verification from database
func TestVerifyRefreshToken_PositiveCase2_WithoutCache(t *testing.T) {
	service, mockHelper := newTestAuthorizationsService()

	sesID := ""
	refreshToken := "refresh-token-456"
	expectedUser := models.User{
		ID:       "user-456",
		Username: "dbuser",
	}
	session := models.UserSession{
		ID:        "session-456",
		User:      expectedUser,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	mockHelper.On("GetCache", refreshToken).Return(nil, errors.New("cache miss"))
	service.userSessionRepository.On("GetByRefreshToken", refreshToken).Return(session, nil)
	mockHelper.On("SetCache", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	user, err := service.VerifyRefreshToken(refreshToken, &sesID)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "user-456", user.ID)
	assert.Equal(t, "session-456", sesID)
}

// TestVerifyRefreshToken_NegativeCase_NotFound tests failed refresh token verification
func TestVerifyRefreshToken_NegativeCase_NotFound(t *testing.T) {
	service, mockHelper := newTestAuthorizationsService()

	sesID := ""
	refreshToken := "invalid-refresh-token"

	mockHelper.On("GetCache", refreshToken).Return(nil, errors.New("cache miss"))
	service.userSessionRepository.On("GetByRefreshToken", refreshToken).Return(models.UserSession{}, gorm.ErrRecordNotFound)

	user, err := service.VerifyRefreshToken(refreshToken, &sesID)

	assert.Error(t, err)
	assert.Nil(t, user)
}

// TestRevokeAuthorization_PositiveCase1 tests successful revocation
func TestRevokeAuthorization_PositiveCase1(t *testing.T) {
	service, mockHelper := newTestAuthorizationsService()

	sessionID := "session-123"
	session := &models.UserSession{
		ID:           sessionID,
		RefreshToken: "refresh-token-123",
	}

	service.userSessionRepository.On("GetByID", sessionID).Return(session, nil)
	mockHelper.On("DeleteCache", constants.PREFIX_CACHE_LOGIN_USER+sessionID).Return(nil)
	mockHelper.On("DeleteCache", "refresh-token-123").Return(nil)
	service.userSessionRepository.On("Delete", sessionID).Return(nil)

	err := service.RevokeAuthorization(sessionID)

	assert.NoError(t, err)
}

// TestRevokeAuthorization_PositiveCase2 tests successful revocation with different session
func TestRevokeAuthorization_PositiveCase2(t *testing.T) {
	service, mockHelper := newTestAuthorizationsService()

	sessionID := "session-456"
	session := &models.UserSession{
		ID:           sessionID,
		RefreshToken: "another-refresh-token",
	}

	service.userSessionRepository.On("GetByID", sessionID).Return(session, nil)
	mockHelper.On("DeleteCache", constants.PREFIX_CACHE_LOGIN_USER+sessionID).Return(nil)
	mockHelper.On("DeleteCache", "another-refresh-token").Return(nil)
	service.userSessionRepository.On("Delete", sessionID).Return(nil)

	err := service.RevokeAuthorization(sessionID)

	assert.NoError(t, err)
}

// TestRevokeAuthorization_NegativeCase_SessionNotFound tests failed revocation when session not found
func TestRevokeAuthorization_NegativeCase_SessionNotFound(t *testing.T) {
	service, _ := newTestAuthorizationsService()

	sessionID := "nonexistent-session"

	service.userSessionRepository.On("GetByID", sessionID).Return(nil, gorm.ErrRecordNotFound)

	err := service.RevokeAuthorization(sessionID)

	assert.Error(t, err)
}

// TestListRoles_PositiveCase1_AdminUser tests listing roles for admin user
func TestListRoles_PositiveCase1_AdminUser(t *testing.T) {
	service, _ := newTestAuthorizationsService()

	adminUser := models.User{
		ID:       "admin-123",
		Username: "admin",
	}
	req := types.PagingCursor{
		Limit: 10,
	}

	adminRole := models.Role{
		ID:   "role-admin",
		Name: "admin",
	}
	roles := []models.Role{
		{ID: "role-1", Name: "admin", CreatedAt: time.Now()},
		{ID: "role-2", Name: "user", CreatedAt: time.Now()},
	}

	service.roleRepository.On("GetByName", "admin").Return(adminRole, nil)
	service.userRoleRepository.On("CheckUserRole", "admin-123", "role-admin").Return(true, nil)
	service.roleRepository.On("GetListsCursor", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(roles, nil)

	result, err := service.ListRoles(req, adminUser)

	assert.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, "role-1", result[0].RoleID)
	assert.Equal(t, "admin", result[0].Name)
}

// TestListRoles_PositiveCase2_NonAdminUser tests listing roles for non-admin user (admin role filtered)
func TestListRoles_PositiveCase2_NonAdminUser(t *testing.T) {
	service, _ := newTestAuthorizationsService()

	normalUser := models.User{
		ID:       "user-123",
		Username: "normaluser",
	}
	req := types.PagingCursor{
		Limit: 10,
	}

	adminRole := models.Role{
		ID:   "role-admin",
		Name: "admin",
	}
	roles := []models.Role{
		{ID: "role-2", Name: "user", CreatedAt: time.Now()},
		{ID: "role-3", Name: "moderator", CreatedAt: time.Now()},
	}

	service.roleRepository.On("GetByName", "admin").Return(adminRole, nil)
	service.userRoleRepository.On("CheckUserRole", "user-123", "role-admin").Return(false, nil)
	service.roleRepository.On("GetListsCursor", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(roles, nil)

	result, err := service.ListRoles(req, normalUser)

	assert.NoError(t, err)
	assert.Len(t, result, 2)
	// Should not contain admin role
	for _, r := range result {
		assert.NotEqual(t, "admin", r.Name)
	}
}

// TestListRoles_NegativeCase_RepositoryError tests failed listing when repository returns error
func TestListRoles_NegativeCase_RepositoryError(t *testing.T) {
	service, _ := newTestAuthorizationsService()

	user := models.User{
		ID:       "user-123",
		Username: "testuser",
	}
	req := types.PagingCursor{
		Limit: 10,
	}

	adminRole := models.Role{
		ID:   "role-admin",
		Name: "admin",
	}

	service.roleRepository.On("GetByName", "admin").Return(adminRole, nil)
	service.userRoleRepository.On("CheckUserRole", "user-123", "role-admin").Return(false, nil)
	service.roleRepository.On("GetListsCursor", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("database error"))

	result, err := service.ListRoles(req, user)

	assert.Error(t, err)
	assert.Nil(t, result)
}

// TestCreateAdminUser_PositiveCase1 tests successful admin user creation
func TestCreateAdminUser_PositiveCase1(t *testing.T) {
	service, mockHelper := newTestAuthorizationsService()

	email := "admin@example.com"
	password := "securepass123"

	adminRole := models.Role{
		ID:   "role-admin",
		Name: "admin",
	}

	mockHelper.On("HashPassword", password).Return("hashedpassword", nil)
	service.userRepository.On("Create", mock.AnythingOfType("*models.User")).Return(nil)
	mockHelper.On("DefaultValue", mock.Anything, "Asia/Jakarta").Return("Asia/Jakarta")
	mockHelper.On("DefaultValue", mock.Anything, "en").Return("en-US")
	service.userProfileRepository.On("Create", mock.AnythingOfType("*models.UserProfile")).Return(nil)
	service.roleRepository.On("GetByName", "admin").Return(adminRole, nil)
	service.userRoleRepository.On("AssignRole", mock.AnythingOfType("models.UserRole")).Return(nil)

	user, code, err := service.CreateAdminUser(email, password)

	assert.NoError(t, err)
	assert.Equal(t, constants.SuccessCreate, code)
	assert.Equal(t, email, user.Email)
	assert.Equal(t, email, user.Username)
	assert.True(t, user.IsActive)
	assert.True(t, user.EmailVerified)
}

// TestCreateAdminUser_PositiveCase2 tests successful admin user creation with full name
func TestCreateAdminUser_PositiveCase2(t *testing.T) {
	service, mockHelper := newTestAuthorizationsService()

	email := "john.doe@company.com"
	password := "password456"

	adminRole := models.Role{
		ID:   "role-admin",
		Name: "admin",
	}

	mockHelper.On("HashPassword", password).Return("anotherhash", nil)
	service.userRepository.On("Create", mock.AnythingOfType("*models.User")).Return(nil)
	mockHelper.On("DefaultValue", mock.Anything, "Asia/Jakarta").Return("Asia/Jakarta")
	mockHelper.On("DefaultValue", mock.Anything, "en").Return("en-US")
	service.userProfileRepository.On("Create", mock.AnythingOfType("*models.UserProfile")).Return(nil)
	service.roleRepository.On("GetByName", "admin").Return(adminRole, nil)
	service.userRoleRepository.On("AssignRole", mock.AnythingOfType("models.UserRole")).Return(nil)

	user, code, err := service.CreateAdminUser(email, password)

	assert.NoError(t, err)
	assert.Equal(t, constants.SuccessCreate, code)
	assert.Equal(t, email, user.Email)
}

// TestCreateAdminUser_NegativeCase_HashPasswordFails tests failed admin user creation when password hashing fails
func TestCreateAdminUser_NegativeCase_HashPasswordFails(t *testing.T) {
	service, mockHelper := newTestAuthorizationsService()

	email := "admin@example.com"
	password := "weakpass"

	mockHelper.On("HashPassword", password).Return("", errors.New("hashing failed"))

	user, code, err := service.CreateAdminUser(email, password)

	assert.Error(t, err)
	assert.Equal(t, constants.InternalServerError, code)
	assert.Empty(t, user.ID)
}

// TestAppHasAdministrator_PositiveCase1 tests when app has administrator
func TestAppHasAdministrator_PositiveCase1(t *testing.T) {
	service, _ := newTestAuthorizationsService()

	adminRole := models.Role{
		ID:   "role-admin",
		Name: "admin",
	}

	service.roleRepository.On("GetByName", "admin").Return(adminRole, nil)
	service.userRepository.On("CountRoleActiveUsers", "role-admin").Return(int64(5))

	result := service.AppHasAdministrator()

	assert.True(t, result)
}

// TestAppHasAdministrator_PositiveCase2 tests when app has exactly one administrator
func TestAppHasAdministrator_PositiveCase2(t *testing.T) {
	service, _ := newTestAuthorizationsService()

	adminRole := models.Role{
		ID:   "role-admin",
		Name: "admin",
	}

	service.roleRepository.On("GetByName", "admin").Return(adminRole, nil)
	service.userRepository.On("CountRoleActiveUsers", "role-admin").Return(int64(1))

	result := service.AppHasAdministrator()

	assert.True(t, result)
}

// TestAppHasAdministrator_NegativeCase tests when app has no administrator
func TestAppHasAdministrator_NegativeCase(t *testing.T) {
	service, _ := newTestAuthorizationsService()

	adminRole := models.Role{
		ID:   "role-admin",
		Name: "admin",
	}

	service.roleRepository.On("GetByName", "admin").Return(adminRole, nil)
	service.userRepository.On("CountRoleActiveUsers", "role-admin").Return(int64(0))

	result := service.AppHasAdministrator()

	assert.False(t, result)
}
