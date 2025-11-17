package repository

import (
	"errors"

	"app/src/models"

	"gorm.io/gorm"
)

type UserProfileRepository interface {
	BaseRepository[models.UserProfile]
	GetByUserID(userID string) (models.UserProfile, error)
}

type userProfileRepository struct {
	BaseRepository[models.UserProfile]
	db *gorm.DB
}

func NewUserProfileRepository(db *gorm.DB) UserProfileRepository {
	// Define the relationships to preload
	relation := []string{
		"User",
	}
	return &userProfileRepository{
		db:             db,
		BaseRepository: NewBaseRepository(db, models.UserProfile{}, relation),
	}
}

func (r *userProfileRepository) GetByUserID(userID string) (models.UserProfile, error) {
	var profile models.UserProfile
	if err := r.db.Where("user_id = ?", userID).First(&profile).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.UserProfile{}, nil
		}
		return models.UserProfile{}, err
	}
	return profile, nil
}
