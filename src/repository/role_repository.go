package repository

import (
	interfaces "app/src/interface"
	"app/src/models"
	helper "app/utils"
	"errors"

	"gorm.io/gorm"
)

type RoleRepository struct {
	Db *gorm.DB
}

func NewRole(db *gorm.DB) (interfaces.RoleInterface) {
	return &RoleRepository{Db: db}
}

func (t *RoleRepository) FindAllRole() ([]models.Role, error) {
	var roles []models.Role
	result := t.Db.Find(&roles)
	return roles, result.Error
}

func (t *RoleRepository) FindRoleById(id uint8) (models.Role, error) {
	var role models.Role
	result := t.Db.First(&role, id)
	return role, result.Error
}

func (t *RoleRepository) FindRole(filter map[string]interface{}) ([]models.Role, error) {
	var roles []models.Role
	tempdb := t.Db
	likeColumn := []string{"name"}
	for key, value := range filter {
		if helper.ContainString(likeColumn, key) {
			tempdb.Where(key+" LIKE %?%", value)
			continue
		}
		tempdb.Where(key, value)
	}
	result := tempdb.Find(&roles)
	return roles, result.Error
}

func (t *RoleRepository) CreateRole(role models.Role) error {
	result := t.Db.Create(&role)
	return result.Error
}

func (t *RoleRepository) UpdateRole(role models.Role) error {
	result := t.Db.Save(&role)
	return result.Error
}

func (t *RoleRepository) DeleteRole(id uint8) error {
	result := t.Db.Delete(&models.Role{}, id)
	return result.Error
}

func (t *RoleRepository) AdminRole() (models.Role, error) {
	var (
		role models.Role
		adminId = 1
	)
	result := t.Db.First(&role, adminId)
	return role, result.Error
}

func (t *RoleRepository) CreateAdminRole() (int, error) {
	var (
		role models.Role
		adminId = uint8(1)
	)
	check, err := t.FindRoleById(adminId)
	if err != nil {
		role = models.Role{
			Id: uint8(adminId),
			Name: "Administrator",
		}	
		
		err = t.CreateRole(role)
		return int(role.Id), err
	}
	
	if check.Id == adminId {
		return 0, errors.New("Role Admin Already Exists")
	}

	return 0, errors.New("Failed to create role admin")
}