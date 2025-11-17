package mocks

import (
	"app/src/models"
	"app/src/types"

	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
)

// MockUserRepository is a mock implementation of repository.UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) BaseQuery() *gorm.DB {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*gorm.DB)
}

func (m *MockUserRepository) Create(user *models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) Update(id string, user *models.User) error {
	args := m.Called(id, user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockUserRepository) GetListsCursor(filter []types.FilterQuery, lastValue string, lastColumn string, sort types.SORTING, limit int) ([]models.User, error) {
	args := m.Called(filter, lastValue, lastColumn, sort, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.User), args.Error(1)
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

func (m *MockUserRepository) GetByUserType(roleName string, limit, offset int) ([]models.User, error) {
	args := m.Called(roleName, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.User), args.Error(1)
}

func (m *MockUserRepository) Activate(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockUserRepository) UpdateLastLogin(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockUserRepository) CountRoleActiveUsers(RoleId string) int64 {
	args := m.Called(RoleId)
	return args.Get(0).(int64)
}

// MockUserSessionRepository is a mock implementation of repository.UserSessionRepository
type MockUserSessionRepository struct {
	mock.Mock
}

func (m *MockUserSessionRepository) BaseQuery() *gorm.DB {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*gorm.DB)
}

func (m *MockUserSessionRepository) Create(session *models.UserSession) error {
	args := m.Called(session)
	return args.Error(0)
}

func (m *MockUserSessionRepository) Update(id string, session *models.UserSession) error {
	args := m.Called(id, session)
	return args.Error(0)
}

func (m *MockUserSessionRepository) Delete(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockUserSessionRepository) GetListsCursor(filter []types.FilterQuery, lastValue string, lastColumn string, sort types.SORTING, limit int) ([]models.UserSession, error) {
	args := m.Called(filter, lastValue, lastColumn, sort, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.UserSession), args.Error(1)
}

func (m *MockUserSessionRepository) GetByID(ID string) (*models.UserSession, error) {
	args := m.Called(ID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserSession), args.Error(1)
}

func (m *MockUserSessionRepository) GetByToken(token string) (models.UserSession, error) {
	args := m.Called(token)
	return args.Get(0).(models.UserSession), args.Error(1)
}

func (m *MockUserSessionRepository) GetByRefreshToken(refreshToken string) (models.UserSession, error) {
	args := m.Called(refreshToken)
	return args.Get(0).(models.UserSession), args.Error(1)
}

func (m *MockUserSessionRepository) GetByUserID(userID string) (*models.UserSession, error) {
	args := m.Called(userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserSession), args.Error(1)
}

func (m *MockUserSessionRepository) DeleteByToken(token string) error {
	args := m.Called(token)
	return args.Error(0)
}

func (m *MockUserSessionRepository) DeleteExpired() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockUserSessionRepository) DeleteUserSessions(userID string) error {
	args := m.Called(userID)
	return args.Error(0)
}

// MockUserProfileRepository is a mock implementation of repository.UserProfileRepository
type MockUserProfileRepository struct {
	mock.Mock
}

func (m *MockUserProfileRepository) BaseQuery() *gorm.DB {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*gorm.DB)
}

func (m *MockUserProfileRepository) Create(profile *models.UserProfile) error {
	args := m.Called(profile)
	return args.Error(0)
}

func (m *MockUserProfileRepository) Update(id string, profile *models.UserProfile) error {
	args := m.Called(id, profile)
	return args.Error(0)
}

func (m *MockUserProfileRepository) Delete(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockUserProfileRepository) GetListsCursor(filter []types.FilterQuery, lastValue string, lastColumn string, sort types.SORTING, limit int) ([]models.UserProfile, error) {
	args := m.Called(filter, lastValue, lastColumn, sort, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.UserProfile), args.Error(1)
}

func (m *MockUserProfileRepository) GetByUserID(userID string) (models.UserProfile, error) {
	args := m.Called(userID)
	return args.Get(0).(models.UserProfile), args.Error(1)
}

// MockRoleRepository is a mock implementation of repository.RoleRepository
type MockRoleRepository struct {
	mock.Mock
}

func (m *MockRoleRepository) BaseQuery() *gorm.DB {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*gorm.DB)
}

func (m *MockRoleRepository) Create(role *models.Role) error {
	args := m.Called(role)
	return args.Error(0)
}

func (m *MockRoleRepository) Update(id string, role *models.Role) error {
	args := m.Called(id, role)
	return args.Error(0)
}

func (m *MockRoleRepository) Delete(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockRoleRepository) GetListsCursor(filter []types.FilterQuery, lastValue string, lastColumn string, sort types.SORTING, limit int) ([]models.Role, error) {
	args := m.Called(filter, lastValue, lastColumn, sort, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Role), args.Error(1)
}

func (m *MockRoleRepository) GetByID(id string) (models.Role, error) {
	args := m.Called(id)
	return args.Get(0).(models.Role), args.Error(1)
}

func (m *MockRoleRepository) GetSystemRoles() ([]models.Role, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Role), args.Error(1)
}

func (m *MockRoleRepository) GetByName(name string) (models.Role, error) {
	args := m.Called(name)
	return args.Get(0).(models.Role), args.Error(1)
}

func (m *MockRoleRepository) GetLists(lastDate string, limit int) ([]models.Role, error) {
	args := m.Called(lastDate, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Role), args.Error(1)
}

// MockUserRoleRepository is a mock implementation of repository.UserRoleRepository
type MockUserRoleRepository struct {
	mock.Mock
}

func (m *MockUserRoleRepository) BaseQuery() *gorm.DB {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*gorm.DB)
}

func (m *MockUserRoleRepository) Create(userRole *models.UserRole) error {
	args := m.Called(userRole)
	return args.Error(0)
}

func (m *MockUserRoleRepository) Update(id string, userRole *models.UserRole) error {
	args := m.Called(id, userRole)
	return args.Error(0)
}

func (m *MockUserRoleRepository) Delete(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockUserRoleRepository) GetListsCursor(filter []types.FilterQuery, lastValue string, lastColumn string, sort types.SORTING, limit int) ([]models.UserRole, error) {
	args := m.Called(filter, lastValue, lastColumn, sort, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.UserRole), args.Error(1)
}

func (m *MockUserRoleRepository) AssignRole(userRole models.UserRole) error {
	args := m.Called(userRole)
	return args.Error(0)
}

func (m *MockUserRoleRepository) RemoveRole(userID, roleID string) error {
	args := m.Called(userID, roleID)
	return args.Error(0)
}

func (m *MockUserRoleRepository) GetUserRoles(userID string) ([]models.UserRole, error) {
	args := m.Called(userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.UserRole), args.Error(1)
}

func (m *MockUserRoleRepository) GetRoleUsers(roleID string) ([]models.UserRole, error) {
	args := m.Called(roleID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.UserRole), args.Error(1)
}

func (m *MockUserRoleRepository) CheckUserRole(userID, roleID string) (bool, error) {
	args := m.Called(userID, roleID)
	return args.Bool(0), args.Error(1)
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

func (m *MockDatabase) DB() *gorm.DB {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*gorm.DB)
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
