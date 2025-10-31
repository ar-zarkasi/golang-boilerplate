package repository

import (
	"errors"

	"app/src/connections"
	"app/src/helpers"
	"app/src/models"

	"gorm.io/gorm"
)

type UserProfileRepository interface {
	Create(profile models.UserProfile) (models.UserProfile, error)
	GetByUserID(userID string) (models.UserProfile, error)
	Update(profile models.UserProfile) error
	Delete(userID string) error
}

type userProfileRepository struct {
	db connections.Database
}

func NewUserProfileRepository() UserProfileRepository {
	helper := helpers.NewHelpers()
	return &userProfileRepository{
		db: helper.GetDatabase(),
	}
}

func (r *userProfileRepository) Create(profile models.UserProfile) (models.UserProfile, error) {
	if err := r.db.DB().Create(&profile).Error; err != nil {
		return models.UserProfile{}, err
	}
	return profile, nil
}

func (r *userProfileRepository) GetByUserID(userID string) (models.UserProfile, error) {
	var profile models.UserProfile
	if err := r.db.DB().Where("user_id = ?", userID).First(&profile).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.UserProfile{}, nil
		}
		return models.UserProfile{}, err
	}
	return profile, nil
}

func (r *userProfileRepository) Update(profile models.UserProfile) error {
	return r.db.DB().Save(&profile).Error
}

func (r *userProfileRepository) Delete(userID string) error {
	return r.db.DB().Delete(&models.UserProfile{}, "user_id = ?", userID).Error
}
