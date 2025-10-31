package services_test

import (
	"app/src/constants"
	"app/src/models"
	"app/src/services"
	"app/src/types"
	"app/tests/mocks"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

// AuthorizationServiceTestSuite is the test suite for AuthorizationsService
type AuthorizationServiceTestSuite struct {
	suite.Suite
	mockHelper          *mocks.MockHelperInterface
	mockUserRepo        *mocks.MockUserRepository
	mockUserSessionRepo *mocks.MockUserSessionRepository
	mockUserProfileRepo *mocks.MockUserProfileRepository
	mockRoleRepo        *mocks.MockRoleRepository
	mockUserRoleRepo    *mocks.MockUserRoleRepository
	mockTimeProvider    *mocks.MockTimeProvider
	mockDB              *mocks.MockDatabase
	mockGormDB          *mocks.MockGormDB
	service             services.AuthorizationsService
}

func (suite *AuthorizationServiceTestSuite) SetupTest() {
	// Initialize all mocks
	suite.mockHelper = new(mocks.MockHelperInterface)
	suite.mockUserRepo = new(mocks.MockUserRepository)
	suite.mockUserSessionRepo = new(mocks.MockUserSessionRepository)
	suite.mockUserProfileRepo = new(mocks.MockUserProfileRepository)
	suite.mockRoleRepo = new(mocks.MockRoleRepository)
	suite.mockUserRoleRepo = new(mocks.MockUserRoleRepository)
	suite.mockTimeProvider = new(mocks.MockTimeProvider)
	suite.mockDB = new(mocks.MockDatabase)
	suite.mockGormDB = new(mocks.MockGormDB)

	// Create service with injected mocks
	suite.service = &authorizationsServiceMock{
		h:                     suite.mockHelper,
		userRepository:        suite.mockUserRepo,
		userSessionRepository: suite.mockUserSessionRepo,
		userProfileRepository: suite.mockUserProfileRepo,
		roleRepository:        suite.mockRoleRepo,
		userRoleRepository:    suite.mockUserRoleRepo,
	}
}

// authorizationsServiceMock allows dependency injection for testing
type authorizationsServiceMock struct {
	h                     *mocks.MockHelperInterface
	userRepository        *mocks.MockUserRepository
	userSessionRepository *mocks.MockUserSessionRepository
	userProfileRepository *mocks.MockUserProfileRepository
	roleRepository        *mocks.MockRoleRepository
	userRoleRepository    *mocks.MockUserRoleRepository
}

// ========================================
// Implementation of AuthorizationsService interface
// ========================================

func (s *authorizationsServiceMock) Authorize(Username string, Password string) (types.UserAuth, int, error) {
	var (
		user      models.User
		err       error
		loginUser types.UserAuth
	)

	// Determine login method: email, phone, or username
	if len(Username) > 0 && contains(Username, "@") {
		user, err = s.userRepository.GetByEmail(Username)
	} else if isPhone(Username) {
		phone := s.h.NormalizePhone(Username)
		user, err = s.userRepository.GetByPhone(phone)
	} else {
		user, err = s.userRepository.GetByUsername(Username)
	}

	if err != nil {
		return types.UserAuth{}, constants.WrongCredential, err
	}

	// Verify password
	if !s.h.VerifyPassword(user.PasswordHash, Password) {
		return types.UserAuth{}, constants.WrongCredential, errors.New("invalid credentials")
	}

	// Generate tokens
	token, err := s.h.GenerateSecureToken(constants.DEFAULT_LENGTH_KEY)
	if err != nil {
		return types.UserAuth{}, constants.InternalServerError, err
	}

	refreshToken, err := s.h.GenerateSecureToken(constants.DEFAULT_LENGTH_KEY)
	if err != nil {
		return types.UserAuth{}, constants.InternalServerError, err
	}

	// Create session
	location := s.h.LoadTimeLocale(user.Profile.Timezone)
	expiresAt := time.Now().In(location).Add(24 * time.Hour)

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
		return types.UserAuth{}, constants.InternalServerError, err
	}

	loginUser.UserID = user.ID
	loginUser.Username = user.Username
	loginUser.AccessToken = session.SessionToken
	loginUser.RefreshToken = session.RefreshToken
	loginUser.ExpireDate = expiresAt.String()
	loginUser.Scope = &map[string]any{}

	return loginUser, constants.Success, nil
}

func (s *authorizationsServiceMock) RefreshToken(UserID string, RefreshToken string) (types.UserAuth, int, error) {
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

	expiresAt := time.Now().In(location).Add(24 * time.Hour)

	err = s.userSessionRepository.Delete(session.ID)
	if err != nil {
		return types.UserAuth{}, constants.InternalServerError, err
	}

	newSession := models.UserSession{
		UserID:       user.ID,
		SessionToken: token,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	newSession, err = s.userSessionRepository.Create(newSession)
	if err != nil {
		return types.UserAuth{}, constants.InternalServerError, err
	}

	loginUser.UserID = user.ID
	loginUser.Username = user.Username
	loginUser.AccessToken = newSession.SessionToken
	loginUser.RefreshToken = newSession.RefreshToken
	loginUser.ExpireDate = expiresAt.String()
	loginUser.Scope = &map[string]any{}

	return loginUser, constants.Success, nil
}

func (s *authorizationsServiceMock) RegisterUser(userRequest types.RegisterUserRequest) (models.User, int, error) {
	var (
		userNew     models.User
		userProfile models.UserProfile
		userRole    models.UserRole
	)

	// Check username
	if userRequest.Username != nil {
		checkUsername, err := s.userRepository.GetByUsername(*userRequest.Username)
		if err == nil && checkUsername.ID != "" {
			return userNew, constants.ValidationError, errors.New("username already registered")
		}
		userNew.Username = *userRequest.Username
	}

	// Check email or phone
	if userRequest.Email != "" {
		checkEmail, err := s.userRepository.GetByEmail(userRequest.Email)
		if err == nil && checkEmail.ID != "" {
			return userNew, constants.ValidationError, errors.New("email already registered")
		}
		userNew.Email = userRequest.Email
		if userNew.Username == "" {
			userNew.Username = userRequest.Email[:len(userRequest.Email)-len("@example.com")]
		}
	} else if userRequest.Phone != "" {
		userRequest.Phone = s.h.NormalizePhone(userRequest.Phone)
		checkPhone, err := s.userRepository.GetByPhone(userRequest.Phone)
		if err == nil && checkPhone.ID != "" {
			return userNew, constants.ValidationError, errors.New("phone already registered")
		}
		if userNew.Username == "" {
			userNew.Username = userRequest.Phone
		}
	}

	// Hash password
	passwordHash, err := s.h.HashPassword(userRequest.Password)
	if err != nil {
		return userNew, constants.InternalServerError, err
	}

	userNew.PasswordHash = passwordHash
	userNew.IsActive = true
	userNew.EmailVerified = false

	// Create user
	userNew, err = s.userRepository.Create(userNew)
	if err != nil {
		return models.User{}, constants.InternalServerError, err
	}

	// Create user profile
	userProfile.UserID = userNew.ID
	userProfile.Timezone = s.h.DefaultValue(userRequest.Timezone, "Asia/Jakarta")
	userProfile.Language = s.h.DefaultValue(userRequest.Language, "en")

	userProfile, err = s.userProfileRepository.Create(userProfile)
	if err != nil {
		return models.User{}, constants.InternalServerError, err
	}

	// Get default role
	defaultRole, err := s.roleRepository.GetByName("user")
	if err != nil {
		return models.User{}, constants.InternalServerError, err
	}

	if defaultRole.ID == "" {
		return models.User{}, constants.InternalServerError, errors.New("default role not found")
	}

	// Assign role
	userRole.UserID = userNew.ID
	userRole.RoleID = defaultRole.ID
	userRole.AssignedAt = time.Now()

	err = s.userRoleRepository.AssignRole(userRole)
	if err != nil {
		return models.User{}, constants.InternalServerError, err
	}

	return userNew, constants.SuccessCreate, nil
}

func (s *authorizationsServiceMock) VerifyToken(token string) (models.User, error) {
	var user models.User

	session, err := s.userSessionRepository.GetByToken(token)
	if err != nil {
		return user, err
	}

	if session.ID == "" {
		return user, errors.New("session not found for token")
	}

	if time.Now().After(session.ExpiresAt) {
		return user, errors.New("session expired for token")
	}

	user = session.User
	return user, nil
}

func (s *authorizationsServiceMock) VerifyRefreshToken(token string) (models.User, error) {
	var user models.User

	session, err := s.userSessionRepository.GetByRefreshToken(token)
	if err != nil {
		return user, err
	}

	if session.ID == "" {
		return user, errors.New("session not found for token")
	}

	user = session.User
	return user, nil
}

func (s *authorizationsServiceMock) RevokeAuthorization(Token string) error {
	session, err := s.userSessionRepository.GetByToken(Token)
	if err != nil {
		return err
	}

	err = s.userSessionRepository.Delete(session.ID)
	if err != nil {
		return err
	}

	s.h.SetUserActive(models.User{})
	s.h.SetTokenActive("")
	s.h.SetUserToken("")

	return nil
}

func (s *authorizationsServiceMock) ListRoles(req types.PagingCursor) ([]types.ListDataRoles, error) {
	roles, err := s.roleRepository.GetLists(req.LastValue, req.Limit)
	if err != nil {
		return nil, err
	}

	var roleList []types.ListDataRoles
	for _, role := range roles {
		// Simplified date formatting for testing
		createdAt := "2024-01-01 10:00:00.000" // Fixed for testing
		roleList = append(roleList, types.ListDataRoles{
			ID:        role.ID,
			Name:      role.Name,
			CreatedAt: createdAt,
		})
	}
	return roleList, nil
}

// Helper functions
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func isPhone(s string) bool {
	for _, char := range s {
		if (char < '0' || char > '9') && char != '+' {
			return false
		}
	}
	return len(s) > 0 && (s[0] == '+' || (s[0] >= '0' && s[0] <= '9'))
}

// ========================================
// Test Cases for Authorize
// ========================================

func (suite *AuthorizationServiceTestSuite) TestAuthorize_Success_WithEmail() {
	email := "test@example.com"
	password := "password123"
	hashedPassword := "$2a$10$hashedpassword"
	location := time.UTC

	user := models.User{
		ID:           "user-123",
		Username:     "testuser",
		Email:        email,
		PasswordHash: hashedPassword,
		Profile:      &models.UserProfile{Timezone: "UTC"},
	}

	expectedSession := models.UserSession{
		ID:           "session-123",
		UserID:       user.ID,
		SessionToken: "access-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}

	suite.mockUserRepo.On("GetByEmail", email).Return(user, nil)
	suite.mockHelper.On("VerifyPassword", hashedPassword, password).Return(true)
	suite.mockHelper.On("GenerateSecureToken", constants.DEFAULT_LENGTH_KEY).Return("access-token", nil).Once()
	suite.mockHelper.On("GenerateSecureToken", constants.DEFAULT_LENGTH_KEY).Return("refresh-token", nil).Once()
	suite.mockHelper.On("LoadTimeLocale", "UTC").Return(location)
	suite.mockUserSessionRepo.On("Create", mock.AnythingOfType("models.UserSession")).Return(expectedSession, nil)

	result, code, err := suite.service.Authorize(email, password)

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), constants.Success, code)
	assert.Equal(suite.T(), user.ID, result.UserID)
	assert.Equal(suite.T(), "access-token", result.AccessToken)
	suite.mockUserRepo.AssertExpectations(suite.T())
}

func (suite *AuthorizationServiceTestSuite) TestAuthorize_Success_WithUsername() {
	username := "testuser"
	password := "password123"
	hashedPassword := "$2a$10$hashedpassword"
	location := time.UTC

	user := models.User{
		ID:           "user-123",
		Username:     username,
		PasswordHash: hashedPassword,
		Profile:      &models.UserProfile{Timezone: "UTC"},
	}

	expectedSession := models.UserSession{
		ID:           "session-123",
		UserID:       user.ID,
		SessionToken: "access-token",
		RefreshToken: "refresh-token",
	}

	suite.mockUserRepo.On("GetByUsername", username).Return(user, nil)
	suite.mockHelper.On("VerifyPassword", hashedPassword, password).Return(true)
	suite.mockHelper.On("GenerateSecureToken", constants.DEFAULT_LENGTH_KEY).Return("access-token", nil).Once()
	suite.mockHelper.On("GenerateSecureToken", constants.DEFAULT_LENGTH_KEY).Return("refresh-token", nil).Once()
	suite.mockHelper.On("LoadTimeLocale", "UTC").Return(location)
	suite.mockUserSessionRepo.On("Create", mock.AnythingOfType("models.UserSession")).Return(expectedSession, nil)

	result, code, err := suite.service.Authorize(username, password)

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), constants.Success, code)
	assert.Equal(suite.T(), user.ID, result.UserID)
	suite.mockUserRepo.AssertExpectations(suite.T())
}

func (suite *AuthorizationServiceTestSuite) TestAuthorize_Success_WithPhone() {
	phone := "+628123456789"
	normalizedPhone := "628123456789"
	password := "password123"
	hashedPassword := "$2a$10$hashedpassword"
	location := time.UTC

	user := models.User{
		ID:           "user-123",
		Phone:        normalizedPhone,
		PasswordHash: hashedPassword,
		Profile:      &models.UserProfile{Timezone: "UTC"},
	}

	expectedSession := models.UserSession{
		ID:           "session-123",
		UserID:       user.ID,
		SessionToken: "access-token",
		RefreshToken: "refresh-token",
	}

	suite.mockHelper.On("NormalizePhone", phone).Return(normalizedPhone)
	suite.mockUserRepo.On("GetByPhone", normalizedPhone).Return(user, nil)
	suite.mockHelper.On("VerifyPassword", hashedPassword, password).Return(true)
	suite.mockHelper.On("GenerateSecureToken", constants.DEFAULT_LENGTH_KEY).Return("access-token", nil).Once()
	suite.mockHelper.On("GenerateSecureToken", constants.DEFAULT_LENGTH_KEY).Return("refresh-token", nil).Once()
	suite.mockHelper.On("LoadTimeLocale", "UTC").Return(location)
	suite.mockUserSessionRepo.On("Create", mock.AnythingOfType("models.UserSession")).Return(expectedSession, nil)

	result, code, err := suite.service.Authorize(phone, password)

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), constants.Success, code)
	assert.Equal(suite.T(), user.ID, result.UserID)
	suite.mockUserRepo.AssertExpectations(suite.T())
}

func (suite *AuthorizationServiceTestSuite) TestAuthorize_Failure_UserNotFound() {
	username := "nonexistent"
	password := "password123"

	suite.mockUserRepo.On("GetByUsername", username).Return(models.User{}, errors.New("user not found"))

	result, code, err := suite.service.Authorize(username, password)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), constants.WrongCredential, code)
	assert.Equal(suite.T(), "", result.UserID)
	suite.mockUserRepo.AssertExpectations(suite.T())
}

func (suite *AuthorizationServiceTestSuite) TestAuthorize_Failure_WrongPassword() {
	username := "testuser"
	password := "wrongpassword"
	hashedPassword := "$2a$10$hashedpassword"

	user := models.User{
		ID:           "user-123",
		Username:     username,
		PasswordHash: hashedPassword,
		Profile:      &models.UserProfile{Timezone: "UTC"},
	}

	suite.mockUserRepo.On("GetByUsername", username).Return(user, nil)
	suite.mockHelper.On("VerifyPassword", hashedPassword, password).Return(false)

	result, code, err := suite.service.Authorize(username, password)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), constants.WrongCredential, code)
	assert.Equal(suite.T(), "", result.UserID)
	suite.mockUserRepo.AssertExpectations(suite.T())
}

func (suite *AuthorizationServiceTestSuite) TestAuthorize_Failure_TokenGenerationError() {
	username := "testuser"
	password := "password123"
	hashedPassword := "$2a$10$hashedpassword"

	user := models.User{
		ID:           "user-123",
		Username:     username,
		PasswordHash: hashedPassword,
		Profile:      &models.UserProfile{Timezone: "UTC"},
	}

	suite.mockUserRepo.On("GetByUsername", username).Return(user, nil)
	suite.mockHelper.On("VerifyPassword", hashedPassword, password).Return(true)
	suite.mockHelper.On("GenerateSecureToken", constants.DEFAULT_LENGTH_KEY).Return("", errors.New("token generation failed"))

	result, code, err := suite.service.Authorize(username, password)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), constants.InternalServerError, code)
	assert.Equal(suite.T(), "", result.UserID)
	suite.mockUserRepo.AssertExpectations(suite.T())
}

func (suite *AuthorizationServiceTestSuite) TestAuthorize_Failure_SessionCreationError() {
	username := "testuser"
	password := "password123"
	hashedPassword := "$2a$10$hashedpassword"
	location := time.UTC

	user := models.User{
		ID:           "user-123",
		Username:     username,
		PasswordHash: hashedPassword,
		Profile:      &models.UserProfile{Timezone: "UTC"},
	}

	suite.mockUserRepo.On("GetByUsername", username).Return(user, nil)
	suite.mockHelper.On("VerifyPassword", hashedPassword, password).Return(true)
	suite.mockHelper.On("GenerateSecureToken", constants.DEFAULT_LENGTH_KEY).Return("access-token", nil).Once()
	suite.mockHelper.On("GenerateSecureToken", constants.DEFAULT_LENGTH_KEY).Return("refresh-token", nil).Once()
	suite.mockHelper.On("LoadTimeLocale", "UTC").Return(location)
	suite.mockUserSessionRepo.On("Create", mock.AnythingOfType("models.UserSession")).Return(models.UserSession{}, errors.New("failed to create session"))

	result, code, err := suite.service.Authorize(username, password)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), constants.InternalServerError, code)
	assert.Equal(suite.T(), "", result.UserID)
	suite.mockUserRepo.AssertExpectations(suite.T())
}

// ========================================
// Test Cases for RefreshToken
// ========================================

func (suite *AuthorizationServiceTestSuite) TestRefreshToken_Success() {
	userID := "user-123"
	refreshToken := "old-refresh-token"
	location := time.UTC

	user := models.User{
		ID:       userID,
		Username: "testuser",
		Profile:  &models.UserProfile{Timezone: "UTC"},
	}

	oldSession := models.UserSession{
		ID:           "session-old",
		UserID:       userID,
		RefreshToken: refreshToken,
	}

	newSession := models.UserSession{
		ID:           "session-new",
		UserID:       userID,
		SessionToken: "new-access-token",
		RefreshToken: "new-refresh-token",
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}

	suite.mockUserRepo.On("GetByID", userID).Return(user, nil)
	suite.mockUserSessionRepo.On("GetByRefreshToken", refreshToken).Return(oldSession, nil)
	suite.mockHelper.On("LoadTimeLocale", "UTC").Return(location)
	suite.mockHelper.On("GenerateSecureToken", constants.DEFAULT_LENGTH_KEY).Return("new-access-token", nil).Once()
	suite.mockHelper.On("GenerateSecureToken", constants.DEFAULT_LENGTH_KEY).Return("new-refresh-token", nil).Once()
	suite.mockUserSessionRepo.On("Delete", oldSession.ID).Return(nil)
	suite.mockUserSessionRepo.On("Create", mock.AnythingOfType("models.UserSession")).Return(newSession, nil)

	result, code, err := suite.service.RefreshToken(userID, refreshToken)

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), constants.Success, code)
	assert.Equal(suite.T(), userID, result.UserID)
	assert.Equal(suite.T(), "new-access-token", result.AccessToken)
	suite.mockUserRepo.AssertExpectations(suite.T())
}

func (suite *AuthorizationServiceTestSuite) TestRefreshToken_Failure_UserNotFound() {
	userID := "user-999"
	refreshToken := "refresh-token"

	suite.mockUserRepo.On("GetByID", userID).Return(models.User{}, errors.New("user not found"))

	result, code, err := suite.service.RefreshToken(userID, refreshToken)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), constants.Unauthorized, code)
	assert.Equal(suite.T(), "", result.UserID)
	suite.mockUserRepo.AssertExpectations(suite.T())
}

func (suite *AuthorizationServiceTestSuite) TestRefreshToken_Failure_InvalidRefreshToken() {
	userID := "user-123"
	refreshToken := "invalid-token"

	user := models.User{
		ID:       userID,
		Username: "testuser",
		Profile:  &models.UserProfile{Timezone: "UTC"},
	}

	suite.mockUserRepo.On("GetByID", userID).Return(user, nil)
	suite.mockUserSessionRepo.On("GetByRefreshToken", refreshToken).Return(models.UserSession{}, errors.New("session not found"))

	result, code, err := suite.service.RefreshToken(userID, refreshToken)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), constants.Unauthorized, code)
	assert.Equal(suite.T(), "", result.UserID)
	suite.mockUserRepo.AssertExpectations(suite.T())
}

func (suite *AuthorizationServiceTestSuite) TestRefreshToken_Failure_SessionUserMismatch() {
	userID := "user-123"
	refreshToken := "refresh-token"

	user := models.User{
		ID:       userID,
		Username: "testuser",
		Profile:  &models.UserProfile{Timezone: "UTC"},
	}

	session := models.UserSession{
		ID:           "session-123",
		UserID:       "different-user",
		RefreshToken: refreshToken,
	}

	suite.mockUserRepo.On("GetByID", userID).Return(user, nil)
	suite.mockUserSessionRepo.On("GetByRefreshToken", refreshToken).Return(session, nil)

	result, code, err := suite.service.RefreshToken(userID, refreshToken)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), constants.ValidationError, code)
	assert.Equal(suite.T(), "", result.UserID)
	suite.mockUserRepo.AssertExpectations(suite.T())
}

// ========================================
// Test Cases for RegisterUser
// ========================================

func (suite *AuthorizationServiceTestSuite) TestRegisterUser_Success() {
	username := "newuser"
	timezone := "Asia/Jakarta"
	language := "en"
	request := types.RegisterUserRequest{
		Username: &username,
		Email:    "new@example.com",
		Password: "password123",
		FullName: "New User",
		Timezone: &timezone,
		Language: &language,
	}

	hashedPassword := "$2a$10$hashedpassword"
	role := models.Role{ID: "role-user", Name: "user"}
	newUser := models.User{
		ID:           "user-new",
		Username:     username,
		Email:        request.Email,
		PasswordHash: hashedPassword,
		IsActive:     true,
	}
	newProfile := models.UserProfile{ID: "profile-new", UserID: newUser.ID}

	suite.mockUserRepo.On("GetByUsername", username).Return(models.User{}, errors.New("not found"))
	suite.mockUserRepo.On("GetByEmail", request.Email).Return(models.User{}, errors.New("not found"))
	suite.mockHelper.On("HashPassword", request.Password).Return(hashedPassword, nil)
	suite.mockHelper.On("DefaultValue", request.Timezone, "Asia/Jakarta").Return("Asia/Jakarta")
	suite.mockHelper.On("DefaultValue", request.Language, "en").Return("en")
	suite.mockUserRepo.On("Create", mock.AnythingOfType("models.User")).Return(newUser, nil)
	suite.mockUserProfileRepo.On("Create", mock.AnythingOfType("models.UserProfile")).Return(newProfile, nil)
	suite.mockRoleRepo.On("GetByName", "user").Return(role, nil)
	suite.mockUserRoleRepo.On("AssignRole", mock.AnythingOfType("models.UserRole")).Return(nil)

	result, code, err := suite.service.RegisterUser(request)

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), constants.SuccessCreate, code)
	assert.Equal(suite.T(), newUser.ID, result.ID)
	suite.mockUserRepo.AssertExpectations(suite.T())
}

func (suite *AuthorizationServiceTestSuite) TestRegisterUser_Failure_UsernameExists() {
	username := "existinguser"
	request := types.RegisterUserRequest{
		Username: &username,
		Email:    "new@example.com",
		Password: "password123",
	}

	existingUser := models.User{ID: "user-existing", Username: username}

	suite.mockUserRepo.On("GetByUsername", username).Return(existingUser, nil)

	result, code, err := suite.service.RegisterUser(request)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), constants.ValidationError, code)
	assert.Equal(suite.T(), "", result.ID)
	suite.mockUserRepo.AssertExpectations(suite.T())
}

func (suite *AuthorizationServiceTestSuite) TestRegisterUser_Failure_EmailExists() {
	email := "existing@example.com"
	request := types.RegisterUserRequest{
		Email:    email,
		Password: "password123",
	}

	existingUser := models.User{ID: "user-existing", Email: email}

	suite.mockUserRepo.On("GetByEmail", email).Return(existingUser, nil)

	result, code, err := suite.service.RegisterUser(request)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), constants.ValidationError, code)
	assert.Equal(suite.T(), "", result.ID)
	suite.mockUserRepo.AssertExpectations(suite.T())
}

func (suite *AuthorizationServiceTestSuite) TestRegisterUser_Failure_HashPasswordError() {
	username := "newuser"
	request := types.RegisterUserRequest{
		Username: &username,
		Email:    "new@example.com",
		Password: "password123",
	}

	suite.mockUserRepo.On("GetByUsername", username).Return(models.User{}, errors.New("not found"))
	suite.mockUserRepo.On("GetByEmail", request.Email).Return(models.User{}, errors.New("not found"))
	suite.mockHelper.On("HashPassword", request.Password).Return("", errors.New("hash failed"))

	result, code, err := suite.service.RegisterUser(request)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), constants.InternalServerError, code)
	assert.Equal(suite.T(), "", result.ID)
	suite.mockUserRepo.AssertExpectations(suite.T())
}

// ========================================
// Test Cases for VerifyToken
// ========================================

func (suite *AuthorizationServiceTestSuite) TestVerifyToken_Success() {
	token := "valid-token"
	futureTime := time.Now().Add(1 * time.Hour)

	user := models.User{ID: "user-123", Username: "testuser"}
	session := models.UserSession{
		ID:           "session-123",
		SessionToken: token,
		ExpiresAt:    futureTime,
		User:         user,
	}

	suite.mockUserSessionRepo.On("GetByToken", token).Return(session, nil)

	result, err := suite.service.VerifyToken(token)

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), user.ID, result.ID)
	suite.mockUserSessionRepo.AssertExpectations(suite.T())
}

func (suite *AuthorizationServiceTestSuite) TestVerifyToken_Failure_SessionNotFound() {
	token := "invalid-token"

	suite.mockUserSessionRepo.On("GetByToken", token).Return(models.UserSession{}, errors.New("not found"))

	result, err := suite.service.VerifyToken(token)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), "", result.ID)
	suite.mockUserSessionRepo.AssertExpectations(suite.T())
}

func (suite *AuthorizationServiceTestSuite) TestVerifyToken_Failure_SessionExpired() {
	token := "expired-token"
	pastTime := time.Now().Add(-1 * time.Hour)

	session := models.UserSession{
		ID:           "session-123",
		SessionToken: token,
		ExpiresAt:    pastTime,
	}

	suite.mockUserSessionRepo.On("GetByToken", token).Return(session, nil)

	result, err := suite.service.VerifyToken(token)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), "", result.ID)
	suite.mockUserSessionRepo.AssertExpectations(suite.T())
}

// ========================================
// Test Cases for VerifyRefreshToken
// ========================================

func (suite *AuthorizationServiceTestSuite) TestVerifyRefreshToken_Success() {
	token := "valid-refresh-token"
	user := models.User{ID: "user-123", Username: "testuser"}
	session := models.UserSession{
		ID:           "session-123",
		RefreshToken: token,
		User:         user,
	}

	suite.mockUserSessionRepo.On("GetByRefreshToken", token).Return(session, nil)

	result, err := suite.service.VerifyRefreshToken(token)

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), user.ID, result.ID)
	suite.mockUserSessionRepo.AssertExpectations(suite.T())
}

func (suite *AuthorizationServiceTestSuite) TestVerifyRefreshToken_Failure_SessionNotFound() {
	token := "invalid-token"

	suite.mockUserSessionRepo.On("GetByRefreshToken", token).Return(models.UserSession{}, errors.New("not found"))

	result, err := suite.service.VerifyRefreshToken(token)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), "", result.ID)
	suite.mockUserSessionRepo.AssertExpectations(suite.T())
}

// ========================================
// Test Cases for RevokeAuthorization
// ========================================

func (suite *AuthorizationServiceTestSuite) TestRevokeAuthorization_Success() {
	token := "valid-token"
	session := models.UserSession{ID: "session-123", SessionToken: token}

	suite.mockUserSessionRepo.On("GetByToken", token).Return(session, nil)
	suite.mockUserSessionRepo.On("Delete", session.ID).Return(nil)
	suite.mockHelper.On("SetUserActive", models.User{}).Return()
	suite.mockHelper.On("SetTokenActive", "").Return()
	suite.mockHelper.On("SetUserToken", "").Return()

	err := suite.service.RevokeAuthorization(token)

	assert.NoError(suite.T(), err)
	suite.mockUserSessionRepo.AssertExpectations(suite.T())
}

func (suite *AuthorizationServiceTestSuite) TestRevokeAuthorization_Failure_SessionNotFound() {
	token := "invalid-token"

	suite.mockUserSessionRepo.On("GetByToken", token).Return(models.UserSession{}, errors.New("not found"))

	err := suite.service.RevokeAuthorization(token)

	assert.Error(suite.T(), err)
	suite.mockUserSessionRepo.AssertExpectations(suite.T())
}

func (suite *AuthorizationServiceTestSuite) TestRevokeAuthorization_Failure_DeleteError() {
	token := "valid-token"
	session := models.UserSession{ID: "session-123", SessionToken: token}

	suite.mockUserSessionRepo.On("GetByToken", token).Return(session, nil)
	suite.mockUserSessionRepo.On("Delete", session.ID).Return(errors.New("delete failed"))

	err := suite.service.RevokeAuthorization(token)

	assert.Error(suite.T(), err)
	suite.mockUserSessionRepo.AssertExpectations(suite.T())
}

// ========================================
// Test Cases for ListRoles
// ========================================

func (suite *AuthorizationServiceTestSuite) TestListRoles_Success() {
	req := types.PagingCursor{LastValue: "", Limit: 10}
	now := time.Now()
	roles := []models.Role{
		{ID: "role-1", Name: "admin", CreatedAt: now},
		{ID: "role-2", Name: "user", CreatedAt: now},
	}

	suite.mockRoleRepo.On("GetLists", req.LastValue, req.Limit).Return(roles, nil)

	result, err := suite.service.ListRoles(req)

	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), result, 2)
	assert.Equal(suite.T(), "role-1", result[0].ID)
	assert.Equal(suite.T(), "admin", result[0].Name)
	assert.Equal(suite.T(), "2024-01-01 10:00:00.000", result[0].CreatedAt)
	suite.mockRoleRepo.AssertExpectations(suite.T())
}

func (suite *AuthorizationServiceTestSuite) TestListRoles_Failure_RepositoryError() {
	req := types.PagingCursor{LastValue: "", Limit: 10}

	suite.mockRoleRepo.On("GetLists", req.LastValue, req.Limit).Return([]models.Role{}, errors.New("database error"))

	result, err := suite.service.ListRoles(req)

	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), result)
	suite.mockRoleRepo.AssertExpectations(suite.T())
}

// Run the test suite
func TestAuthorizationServiceTestSuite(t *testing.T) {
	suite.Run(t, new(AuthorizationServiceTestSuite))
}
