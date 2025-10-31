package repository

import (
	"errors"

	"app/src/connections"
	"app/src/helpers"
	"app/src/models"

	"gorm.io/gorm"
)

type UserRepository interface {
	Create(user models.User) (models.User, error)
	GetByID(id string) (models.User, error)
	GetByEmail(email string) (models.User, error)
	GetByUsername(username string) (models.User, error)
	GetByPhone(phone string) (models.User, error)
	GetByCompanyID(companyID string, limit, offset int) ([]models.User, error)
	GetByUserType(userType string, limit, offset int) ([]models.User, error)
	Update(user models.User) error
	Delete(id string) error
	Activate(id string) error
	UpdateLastLogin(id string) error
}

type userRepository struct {
	db connections.Database
}

func NewUserRepository() UserRepository {
	helper := helpers.NewHelpers()
	return &userRepository{
		db: helper.GetDatabase(),
	}
}

func (r *userRepository) getBaseQuery() *gorm.DB {
	return r.db.DB().Preload("Profile").Preload("UserRoles.Role").Preload("Sessions")
}

func (r *userRepository) Create(user models.User) (models.User, error) {
	if err := r.db.DB().Create(&user).Error; err != nil {
		return models.User{}, err
	}
	return user, nil
}

func (r *userRepository) GetByID(id string) (models.User, error) {
	var user models.User
	if err := r.getBaseQuery().Where("id = ? AND is_active = ?", id, true).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.User{}, nil
		}
		return models.User{}, err
	}
	return user, nil
}

func (r *userRepository) GetByEmail(email string) (models.User, error) {
	var user models.User
	if err := r.getBaseQuery().Where("email = ? AND is_active = ?", email, true).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.User{}, nil
		}
		return models.User{}, err
	}
	return user, nil
}

func (r *userRepository) GetByUsername(username string) (models.User, error) {
	var user models.User
	if err := r.getBaseQuery().Where("username = ? AND is_active = ?", username, true).First(&user).Error; err != nil {
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
	if err := r.getBaseQuery().Where("phone = ? AND is_active = ?", phone, true).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.User{}, nil
		}
		return models.User{}, err
	}
	return user, nil
}

func (r *userRepository) GetByCompanyID(companyID string, limit, offset int) ([]models.User, error) {
	var users []models.User
	query := r.getBaseQuery().Preload("Profile").Where("company_id = ? AND is_active = ?", companyID, true)
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

func (r *userRepository) GetByUserType(userType string, limit, offset int) ([]models.User, error) {
	var users []models.User
	query := r.getBaseQuery().Where("user_type = ? AND is_active = ?", userType, true)
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

func (r *userRepository) Update(user models.User) error {
	return r.db.DB().Save(&user).Error
}

func (r *userRepository) Delete(id string) error {
	return r.db.DB().Model(&models.User{}).Where("id = ?", id).Update("is_active", false).Error
}

func (r *userRepository) Activate(id string) error {
	return r.db.DB().Model(&models.User{}).Where("id = ?", id).Update("is_active", true).Error
}

func (r *userRepository) UpdateLastLogin(id string) error {
	return r.db.DB().Model(&models.User{}).Where("id = ?", id).Update("last_login_at", gorm.Expr("CURRENT_TIMESTAMP")).Error
}
