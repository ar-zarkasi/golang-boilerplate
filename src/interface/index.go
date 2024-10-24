package interfaces

import (
	"app/src/http/response"
	"app/src/models"
	"time"

	"github.com/google/uuid"
)

type RoleInterface interface {
	FindAllRole() ([]models.Role, error)
	FindRoleById(id uint8) (role *models.Role, err error)
	FindRole(filter map[string]interface{}) (user []models.Role, err error)
	CreateRole(name string) (*models.Role, error)
	UpdateRole(user models.Role) error
	DeleteRole(id uint8) error
	AdminRole() (role *models.Role, err error)
}

type UserInterface interface {
	FindAllUser() ([]models.User, error)
	FindUserById(id uuid.UUID) (user *models.User, err error)
	FindUser(filter map[string]interface{}) (user []models.User, err error)
	CreateUser(user models.User) error
	UpdateUser(user models.User) error
	DeleteUser(id uuid.UUID) error
}

type AuthInterface interface {
	FindToken(token string) (login models.Authentication, err error)
	FindTokenByUserId(userId string) (login []models.Authentication, err error)
	Signin(user models.User, token string, expired *time.Time, metadata *interface{}) (*response.TokenResponse, error)
	DeleteToken(login models.Authentication) error
	DeleteTokenByID(id ...uint64) error
}