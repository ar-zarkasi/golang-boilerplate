package interfaces

import (
	"app/src/models"

	"github.com/google/uuid"
)

type RoleInterface interface {
	FindAllRole() ([]models.Role, error)
	FindRoleById(id uint8) (role models.Role, err error)
	FindRole(filter map[string]interface{}) (user []models.Role, err error)
	CreateRole(user models.Role) error
	UpdateRole(user models.Role) error
	DeleteRole(id uint8) error
	AdminRole() (role models.Role, err error)
	CreateAdminRole() (int, error)
}

type UserInterface interface {
	FindAllUser() ([]models.User, error)
	FindUserById(id uuid.UUID) (user models.User, err error)
	FindUser(filter map[string]interface{}) (user []models.User, err error)
	CreateUser(user models.User) error
	UpdateUser(user models.User) error
	DeleteUser(id uuid.UUID) error
}