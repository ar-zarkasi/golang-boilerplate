package repository

import (
	"errors"

	"app/src/models"

	"gorm.io/gorm"
)

type UserRepository interface {
	BaseRepository[models.User]
	GetByID(id string) (models.User, error)
	GetByEmail(email string) (models.User, error)
	GetByUsername(username string) (models.User, error)
	GetByPhone(phone string) (models.User, error)
	GetByUserType(roleName string, limit, offset int) ([]models.User, error)
	Activate(id string) error
	UpdateLastLogin(id string) error
	CountRoleActiveUsers(RoleId string) int64
}

type userRepository struct {
	BaseRepository[models.User]
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	// Define the relationships to preload
	relation := []string{
		"Profile",
		"UserRoles",
		"UserRoles.Role",
		"UserRoles.AssignedByUser",
		"Sessions",
	}
	return &userRepository{
		db:             db,
		BaseRepository: NewBaseRepository(db, models.User{}, relation),
	}
}

func (r *userRepository) GetByID(id string) (models.User, error) {
	var user models.User
	if err := r.BaseQuery().Where("id = ? AND is_active = ?", id, true).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.User{}, nil
		}
		return models.User{}, err
	}
	return user, nil
}

func (r *userRepository) GetByEmail(email string) (models.User, error) {
	var user models.User
	if err := r.BaseQuery().Where("email = ? AND is_active = ?", email, true).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.User{}, nil
		}
		return models.User{}, err
	}
	return user, nil
}

func (r *userRepository) GetByUsername(username string) (models.User, error) {
	var user models.User
	if err := r.BaseQuery().Where("username = ? AND is_active = ?", username, true).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.User{}, nil
		}
		return models.User{}, err
	}
	return user, nil
}

func (r *userRepository) GetByPhone(phone string) (models.User, error) {
	// Normalize phone number if necessary
	var user models.User
	if err := r.BaseQuery().Where("phone = ? AND is_active = ?", phone, true).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.User{}, nil
		}
		return models.User{}, err
	}
	return user, nil
}

func (r *userRepository) GetByUserType(roleName string, limit, offset int) ([]models.User, error) {
	var users []models.User
	query := r.BaseQuery().Preload("UserRoles.Role", "name LIKE '%?%'", roleName).Where("is_active = ?", true)
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}
	if err := query.Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}

func (r *userRepository) Activate(id string) error {
	return r.db.Model(&models.User{}).Where("id = ?", id).Update("is_active", true).Error
}

func (r *userRepository) UpdateLastLogin(id string) error {
	return r.db.Model(&models.User{}).Where("id = ?", id).Update("last_login_at", gorm.Expr("CURRENT_TIMESTAMP")).Error
}

func (r *userRepository) CountRoleActiveUsers(RoleId string) int64 {
	count := int64(0)
	err := r.BaseQuery().Preload("UserRoles", "role_id = ?", RoleId).Preload("UserRoles.Role").Where("is_active = ?", true).Count(&count).Error
	if err != nil {
		return 0
	}
	return count
}
