package repository

import (
	"app/src/models"

	"gorm.io/gorm"
)

type UserRoleRepository interface {
	BaseRepository[models.UserRole]
	AssignRole(userRole models.UserRole) error
	RemoveRole(userID, roleID string) error
	GetUserRoles(userID string) ([]models.UserRole, error)
	GetRoleUsers(roleID string) ([]models.UserRole, error)
	CheckUserRole(userID, roleID string) (bool, error)
}

type userRoleRepository struct {
	BaseRepository[models.UserRole]
	db *gorm.DB
}

func NewUserRoleRepository(db *gorm.DB) UserRoleRepository {
	// Define the relationships to preload
	relation := []string{
		"User",
		"Role",
		"AssignedByUser",
	}
	return &userRoleRepository{
		db:             db,
		BaseRepository: NewBaseRepository(db, models.UserRole{}, relation),
	}
}

func (r *userRoleRepository) AssignRole(userRole models.UserRole) error {
	return r.db.Create(&userRole).Error
}

func (r *userRoleRepository) RemoveRole(userID, roleID string) error {
	return r.db.Delete(&models.UserRole{}, "user_id = ? AND role_id = ?", userID, roleID).Error
}

func (r *userRoleRepository) GetUserRoles(userID string) ([]models.UserRole, error) {
	var userRoles []models.UserRole
	if err := r.db.Preload("Role").Where("user_id = ?", userID).Find(&userRoles).Error; err != nil {
		return nil, err
	}
	return userRoles, nil
}

func (r *userRoleRepository) GetRoleUsers(roleID string) ([]models.UserRole, error) {
	var userRoles []models.UserRole
	if err := r.db.Preload("User").Where("role_id = ?", roleID).Find(&userRoles).Error; err != nil {
		return nil, err
	}
	return userRoles, nil
}

func (r *userRoleRepository) CheckUserRole(userID, roleID string) (bool, error) {
	var count int64
	if err := r.db.Model(&models.UserRole{}).Where("user_id = ? AND role_id = ?", userID, roleID).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}
