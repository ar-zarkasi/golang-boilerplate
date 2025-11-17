package repository

import (
	"errors"

	"app/src/models"

	"gorm.io/gorm"
)

type RoleRepository interface {
	BaseRepository[models.Role]

	GetByID(id string) (models.Role, error)
	GetSystemRoles() ([]models.Role, error)
	GetByName(name string) (models.Role, error)
	GetLists(lastDate string, limit int) ([]models.Role, error)
}

type roleRepository struct {
	BaseRepository[models.Role]
	db *gorm.DB
}

func NewRoleRepository(db *gorm.DB) RoleRepository {
	// Define the relationships to preload
	relation := []string{
		"UserRoles",
		"UserRoles.User",
		"UserRoles.Role",
		"UserRoles.AssignedByUser",
	}
	return &roleRepository{
		db:             db,
		BaseRepository: NewBaseRepository(db, models.Role{}, relation),
	}
}

func (r *roleRepository) GetLists(lastDate string, limit int) ([]models.Role, error) {
	var roles []models.Role
	query := r.db

	if lastDate != "" {
		query = query.Where("created_at > ?", lastDate)
	}

	if err := query.Limit(limit).Find(&roles).Error; err != nil {
		return nil, err
	}
	return roles, nil
}

func (r *roleRepository) GetByID(id string) (models.Role, error) {
	var role models.Role
	if err := r.db.Where("id = ?", id).First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.Role{}, nil
		}
		return models.Role{}, err
	}
	return role, nil
}

func (r *roleRepository) GetSystemRoles() ([]models.Role, error) {
	var roles []models.Role
	if err := r.db.Where("is_system_role = ?", true).Find(&roles).Error; err != nil {
		return nil, err
	}
	return roles, nil
}

func (r *roleRepository) GetByName(name string) (models.Role, error) {
	var role models.Role
	if err := r.db.Where("(is_system_role = ?) AND name = ?", true, name).First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.Role{}, nil
		}
		return models.Role{}, err
	}
	return role, nil
}
