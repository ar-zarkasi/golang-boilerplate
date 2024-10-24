package testing

import (
	interfaces "app/src/interface"

	"app/src/models"

	"github.com/stretchr/testify/mock"
)

type RoleRepositoryMock struct {
	Db *mock.Mock
}

func NewRoleMock(db *mock.Mock) (interfaces.RoleInterface) {
	return &RoleRepositoryMock{Db: &mock.Mock{}}
}

func switchInterfaceToModelRole(v interface{}) *models.Role {
	var role models.Role
	switch v.(type) {
	case models.Role:
		role = v.(models.Role)
	default:
		return (*models.Role)(nil)
	}
	return &role
}
func switchToError(v interface{}) error {
	var err error
	switch v.(type) {
	case error:
		err = v.(error)
	default:
		err = nil
	}
	return err
}


func (t *RoleRepositoryMock) FindAllRole() ([]models.Role, error) {
	m := t.Db.Called()
	err := switchToError(m.Get(1))

	return m.Get(0).([]models.Role), err
}

func (t *RoleRepositoryMock) FindRoleById(id uint8) (role *models.Role, err error) {
	m := t.Db.Called(id)
	role = switchInterfaceToModelRole(m.Get(0))
	err = switchToError(m.Get(1))
	return role, err
}
func (t *RoleRepositoryMock) FindRole(filter map[string]interface{}) (user []models.Role, err error) {
	m := t.Db.Called(filter)
	user = m.Get(0).([]models.Role)
	err = switchToError(m.Get(1))
	return user, err
}
func (t *RoleRepositoryMock) CreateRole(name string) (*models.Role, error) {
	m := t.Db.Called(name)
	var (
		role *models.Role
		err error
	)
	role = switchInterfaceToModelRole(m.Get(0))
	err = switchToError(m.Get(1))
	return role, err
}
func (t *RoleRepositoryMock) UpdateRole(user models.Role) error {
	m := t.Db.Called(user)
	err := switchToError(m.Get(0))
	return err
}
func (t *RoleRepositoryMock) DeleteRole(id uint8) error {
	m := t.Db.ExpectedCalls
	return m[1].Arguments.Error(0)
}
func (t *RoleRepositoryMock) AdminRole() (role *models.Role, err error) {
	m := t.Db.Called()
	role = switchInterfaceToModelRole(m.Get(0))
	err = switchToError(m.Get(1))
	return role , err
}