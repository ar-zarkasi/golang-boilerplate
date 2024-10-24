package testing

import (
	"app/src/http/response"
	interfaces "app/src/interface"
	"app/src/models"
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
	err = switchToError(m.Get(1))
	return login, err
}
func (t *AuthRepositoryMock) Signin(user models.User, token string, expired *time.Time, metadata *interface{}) (*response.TokenResponse, error){
	m := t.Db.Called(user, token, expired, metadata)
	resp := m.Get(0).(*response.TokenResponse)
	err := switchToError(m.Get(1))
	return resp, err
}
func (t *AuthRepositoryMock) DeleteToken(login models.Authentication) error{
	m := t.Db.Called(login)
	return switchToError(m.Get(0))
}
func (t *AuthRepositoryMock) DeleteTokenByID(id ...uint64) error{
	m := t.Db.Called(id)
	return switchToError(m.Get(0))
}