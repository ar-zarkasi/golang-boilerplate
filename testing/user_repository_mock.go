package testing

import (
	interfaces "app/src/interface"
	"app/src/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

type UserRepositoryMock struct {
	Db *mock.Mock
}

func NewUserMock(db *mock.Mock) (interfaces.UserInterface) {
	return &UserRepositoryMock{Db: &mock.Mock{}}
}

func switchInterfaceToModelUser(v interface{}) *models.User {
	var role models.User
	switch v.(type) {
	case models.User:
		role = v.(models.User)
	default:
		return (*models.User)(nil)
	}
	return &role
}

func (t *UserRepositoryMock) FindAllUser() ([]models.User, error) {
	m := t.Db.Called()
	user := m.Get(0).([]models.User)
	err := switchToError(m.Get(1))
	return user, err
}
func (t *UserRepositoryMock) FindUserById(id uuid.UUID) (user *models.User, err error) {
	m := t.Db.Called(id)
	user = switchInterfaceToModelUser(m.Get(0))
	err = switchToError(m.Get(1))
	return user, err
}
func (t *UserRepositoryMock) FindUser(filter map[string]interface{}) (user []models.User, err error) {
	m := t.Db.Called(filter)
	user = m.Get(0).([]models.User)
	err = switchToError(m.Get(1))
	return user, err
}
func (t *UserRepositoryMock) CreateUser(user models.User) error {
	m := t.Db.Called(user)
	err := switchToError(m.Get(0))
	return err
}
func (t *UserRepositoryMock) UpdateUser(user models.User) error {
	m := t.Db.Called(user)
	return switchToError(m.Get(0))
}
func (t *UserRepositoryMock) DeleteUser(id uuid.UUID) error {
	m := t.Db.Called(id)
	return switchToError(m.Get(0))
}