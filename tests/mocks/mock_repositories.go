package mocks

import (
	"app/src/models"

	"github.com/stretchr/testify/mock"
)

// MockUserRepository is a mock implementation of repository.UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(user models.User) (models.User, error) {
	args := m.Called(user)
	return args.Get(0).(models.User), args.Error(1)
}

func (m *MockUserRepository) GetByID(id string) (models.User, error) {
	args := m.Called(id)
	return args.Get(0).(models.User), args.Error(1)
}

func (m *MockUserRepository) GetByEmail(email string) (models.User, error) {
	args := m.Called(email)
	return args.Get(0).(models.User), args.Error(1)
}

func (m *MockUserRepository) GetByUsername(username string) (models.User, error) {
	args := m.Called(username)
	return args.Get(0).(models.User), args.Error(1)
}

func (m *MockUserRepository) GetByPhone(phone string) (models.User, error) {
	args := m.Called(phone)
	return args.Get(0).(models.User), args.Error(1)
}

func (m *MockUserRepository) GetByCompanyID(companyID string, limit, offset int) ([]models.User, error) {
	args := m.Called(companyID, limit, offset)
	return args.Get(0).([]models.User), args.Error(1)
}

func (m *MockUserRepository) GetByUserType(userType string, limit, offset int) ([]models.User, error) {
	args := m.Called(userType, limit, offset)
	return args.Get(0).([]models.User), args.Error(1)
}

func (m *MockUserRepository) Update(user models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockUserRepository) Activate(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockUserRepository) UpdateLastLogin(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

// MockUserSessionRepository is a mock implementation of repository.UserSessionRepository
type MockUserSessionRepository struct {
	mock.Mock
}

func (m *MockUserSessionRepository) Create(session models.UserSession) (models.UserSession, error) {
	args := m.Called(session)
	return args.Get(0).(models.UserSession), args.Error(1)
}

func (m *MockUserSessionRepository) GetByToken(token string) (models.UserSession, error) {
	args := m.Called(token)
	return args.Get(0).(models.UserSession), args.Error(1)
}

func (m *MockUserSessionRepository) GetByRefreshToken(refreshToken string) (models.UserSession, error) {
	args := m.Called(refreshToken)
	return args.Get(0).(models.UserSession), args.Error(1)
}

func (m *MockUserSessionRepository) Delete(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockUserSessionRepository) DeleteByUserID(userID string) error {
	args := m.Called(userID)
	return args.Error(0)
}

// MockUserProfileRepository is a mock implementation of repository.UserProfileRepository
type MockUserProfileRepository struct {
	mock.Mock
}

func (m *MockUserProfileRepository) Create(profile models.UserProfile) (models.UserProfile, error) {
	args := m.Called(profile)
	return args.Get(0).(models.UserProfile), args.Error(1)
}

func (m *MockUserProfileRepository) GetByUserID(userID string) (models.UserProfile, error) {
	args := m.Called(userID)
	return args.Get(0).(models.UserProfile), args.Error(1)
}

func (m *MockUserProfileRepository) Update(profile models.UserProfile) error {
	args := m.Called(profile)
	return args.Error(0)
}

func (m *MockUserProfileRepository) Delete(userID string) error {
	args := m.Called(userID)
	return args.Error(0)
}

// MockRoleRepository is a mock implementation of repository.RoleRepository
type MockRoleRepository struct {
	mock.Mock
}

func (m *MockRoleRepository) GetByName(name string) (models.Role, error) {
	args := m.Called(name)
	return args.Get(0).(models.Role), args.Error(1)
}

func (m *MockRoleRepository) GetLists(lastValue string, limit int) ([]models.Role, error) {
	args := m.Called(lastValue, limit)
	return args.Get(0).([]models.Role), args.Error(1)
}

func (m *MockRoleRepository) Create(role models.Role) (models.Role, error) {
	args := m.Called(role)
	return args.Get(0).(models.Role), args.Error(1)
}

func (m *MockRoleRepository) Update(role models.Role) error {
	args := m.Called(role)
	return args.Error(0)
}

func (m *MockRoleRepository) Delete(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

// MockUserRoleRepository is a mock implementation of repository.UserRoleRepository
type MockUserRoleRepository struct {
	mock.Mock
}

func (m *MockUserRoleRepository) AssignRole(userRole models.UserRole) error {
	args := m.Called(userRole)
	return args.Error(0)
}

func (m *MockUserRoleRepository) RevokeRole(userID, roleID string) error {
	args := m.Called(userID, roleID)
	return args.Error(0)
}

func (m *MockUserRoleRepository) GetUserRoles(userID string) ([]models.UserRole, error) {
	args := m.Called(userID)
	return args.Get(0).([]models.UserRole), args.Error(1)
}

// MockTimeProvider is a mock implementation of helpers.TimeProvider
type MockTimeProvider struct {
	mock.Mock
}

func (m *MockTimeProvider) Now() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockTimeProvider) FormattedDate(date string, format string) string {
	args := m.Called(date, format)
	return args.String(0)
}

// MockDatabase is a mock implementation of connections.Database
type MockDatabase struct {
	mock.Mock
}

func (m *MockDatabase) DB() interface{} {
	args := m.Called()
	return args.Get(0)
}

func (m *MockDatabase) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDatabase) Ping() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDatabase) Migration() error {
	args := m.Called()
	return args.Error(0)
}

// MockGormDB is a mock for GORM DB
type MockGormDB struct {
	mock.Mock
}

func (m *MockGormDB) Begin() *MockGormDB {
	m.Called()
	return m
}

func (m *MockGormDB) Commit() *MockGormDB {
	m.Called()
	return m
}

func (m *MockGormDB) Rollback() *MockGormDB {
	m.Called()
	return m
}
