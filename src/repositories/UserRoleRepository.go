package repository

import (
	"app/src/connections"
	"app/src/helpers"
	"app/src/models"
)

type UserRoleRepository interface {
	AssignRole(userRole models.UserRole) error
	RemoveRole(userID, roleID string) error
	GetUserRoles(userID string) ([]models.UserRole, error)
	GetRoleUsers(roleID string) ([]models.UserRole, error)
	CheckUserRole(userID, roleID string) (bool, error)
}

type userRoleRepository struct {
	db connections.Database
}

func NewUserRoleRepository() UserRoleRepository {
	helper := helpers.NewHelpers()
	return &userRoleRepository{
		db: helper.GetDatabase(),
	}
}

func (r *userRoleRepository) AssignRole(userRole models.UserRole) error {
	return r.db.DB().Create(&userRole).Error
}

func (r *userRoleRepository) RemoveRole(userID, roleID string) error {
	return r.db.DB().Delete(&models.UserRole{}, "user_id = ? AND role_id = ?", userID, roleID).Error
}

func (r *userRoleRepository) GetUserRoles(userID string) ([]models.UserRole, error) {
	var userRoles []models.UserRole
	if err := r.db.DB().Preload("Role").Where("user_id = ?", userID).Find(&userRoles).Error; err != nil {
		return nil, err
	}
	return userRoles, nil
}

func (r *userRoleRepository) GetRoleUsers(roleID string) ([]models.UserRole, error) {
	var userRoles []models.UserRole
	if err := r.db.DB().Preload("User").Where("role_id = ?", roleID).Find(&userRoles).Error; err != nil {
		return nil, err
	}
	return userRoles, nil
}

func (r *userRoleRepository) CheckUserRole(userID, roleID string) (bool, error) {
	var count int64
	if err := r.db.DB().Model(&models.UserRole{}).Where("user_id = ? AND role_id = ?", userID, roleID).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}
