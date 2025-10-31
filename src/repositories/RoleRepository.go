package repository

import (
	"context"
	"errors"

	"app/src/connections"
	"app/src/helpers"
	"app/src/models"

	"gorm.io/gorm"
)

type RoleRepository interface {
	Create(role models.Role) (models.Role, error)
	GetByID(id string) (models.Role, error)
	GetSystemRoles(ctx context.Context) ([]models.Role, error)
	GetByName(name string) (models.Role, error)
	Update(role models.Role) error
	Delete(id string) error
	GetLists(lastDate string, limit int) ([]models.Role, error)
}

type roleRepository struct {
	db connections.Database
}

func NewRoleRepository() RoleRepository {
	helper := helpers.NewHelpers()
	return &roleRepository{
		db: helper.GetDatabase(),
	}
}

func (r *roleRepository) GetLists(lastDate string, limit int) ([]models.Role, error) {
	var roles []models.Role
	query := r.db.DB().Model(&models.Role{})

	if lastDate != "" {
		query = query.Where("created_at > ?", lastDate)
	}

	if err := query.Limit(limit).Find(&roles).Error; err != nil {
		return nil, err
	}
	return roles, nil
}

func (r *roleRepository) Create(role models.Role) (models.Role, error) {
	if err := r.db.DB().Create(&role).Error; err != nil {
		return models.Role{}, err
	}
	return role, nil
}

func (r *roleRepository) GetByID(id string) (models.Role, error) {
	var role models.Role
	if err := r.db.DB().Where("id = ?", id).First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.Role{}, nil
		}
		return models.Role{}, err
	}
	return role, nil
}

func (r *roleRepository) GetSystemRoles(ctx context.Context) ([]models.Role, error) {
	var roles []models.Role
	if err := r.db.DB().Where("is_system_role = ?", true).Find(&roles).Error; err != nil {
		return nil, err
	}
	return roles, nil
}

func (r *roleRepository) GetByName(name string) (models.Role, error) {
	var role models.Role
	if err := r.db.DB().Where("(is_system_role = ?) AND name = ?", true, name).First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.Role{}, nil
		}
		return models.Role{}, err
	}
	return role, nil
}

func (r *roleRepository) Update(role models.Role) error {
	return r.db.DB().Save(&role).Error
}

func (r *roleRepository) Delete(id string) error {
	return r.db.DB().Delete(&models.Role{}, "id = ?", id).Error
}
