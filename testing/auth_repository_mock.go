package testing

import (
	interfaces "app/src/interface"
	"app/src/models"
	"fmt"
	"time"

	"github.com/stretchr/testify/mock"
)

type AuthRepositoryMock struct {
	Db *mock.Mock
}

func NewAuthMock(db *mock.Mock) (interfaces.AuthInterface) {
	return &AuthRepositoryMock{Db: &mock.Mock{}}
}

func switchInterfaceToModelAuth(v interface{}) *models.Authentication {
	var role models.Authentication
	switch v.(type) {
	case models.Authentication:
		role = v.(models.Authentication)
	default:
		return (*models.Authentication)(nil)
	}
	return &role
}

func (t *AuthRepositoryMock) FindToken(token string) (login models.Authentication, err error){
	m := t.Db.Called(token)
	login = *switchInterfaceToModelAuth(m.Get(0))
	err = switchToError(m.Get(1))
	return login, err
}
func (t *AuthRepositoryMock) FindTokenByUserId(userId string) (login []models.Authentication, err error){
	m := t.Db.Called(userId)
	login = m.Get(0).([]models.Authentication)
	fmt.Println("Nilai login", login)
	err = switchToError(m.Get(1))
	return login, err
}
func (t *AuthRepositoryMock) Signin(user_id string, token string, expired *time.Time, metadata *interface{}) error{
	m := t.Db.Called(user_id, token, expired, metadata)
	err := switchToError(m.Get(0))
	return err
}
func (t *AuthRepositoryMock) DeleteToken(login models.Authentication) error{
	m := t.Db.Called(login)
	return switchToError(m.Get(0))
}
func (t *AuthRepositoryMock) DeleteTokenByID(id ...uint64) error{
	m := t.Db.Called(id)
	return switchToError(m.Get(0))
}