package repository

import (
	"errors"

	"app/src/connections"
	"app/src/helpers"
	"app/src/models"

	"gorm.io/gorm"
)

type UserSessionRepository interface {
	Create(session models.UserSession) (models.UserSession, error)
	GetByToken(token string) (models.UserSession, error)
	GetByRefreshToken(refreshToken string) (models.UserSession, error)
	GetByUserID(userID string) ([]models.UserSession, error)
	Update(session models.UserSession) error
	Delete(id string) error
	DeleteByToken(token string) error
	DeleteExpired() error
	DeleteUserSessions(userID string) error
}

type userSessionRepository struct {
	db connections.Database
}

func NewUserSessionRepository() UserSessionRepository {
	helper := helpers.NewHelpers()
	return &userSessionRepository{
		db: helper.GetDatabase(),
	}
}

func (r *userSessionRepository) getBaseQuery() *gorm.DB {
	return r.db.DB().Preload("User").Preload("User.Profile").Preload("User.UserRoles.Role")
}

func (r *userSessionRepository) Create(session models.UserSession) (models.UserSession, error) {
	if err := r.db.DB().Create(&session).Error; err != nil {
		return models.UserSession{}, err
	}
	return session, nil
}

func (r *userSessionRepository) GetByToken(token string) (models.UserSession, error) {
	var session models.UserSession
	if err := r.getBaseQuery().Where("session_token = ? AND expires_at > CURRENT_TIMESTAMP", token).First(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.UserSession{}, nil
		}
		return models.UserSession{}, err
	}
	return session, nil
}

func (r *userSessionRepository) GetByRefreshToken(refreshToken string) (models.UserSession, error) {
	var session models.UserSession
	if err := r.getBaseQuery().Where("refresh_token = ?", refreshToken).First(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.UserSession{}, nil
		}
		return models.UserSession{}, err
	}
	return session, nil
}

func (r *userSessionRepository) GetByUserID(userID string) ([]models.UserSession, error) {
	var sessions []models.UserSession
	if err := r.getBaseQuery().Where("user_id = ? AND expires_at > CURRENT_TIMESTAMP", userID).Find(&sessions).Error; err != nil {
		return nil, err
	}
	return sessions, nil
}

func (r *userSessionRepository) Update(session models.UserSession) error {
	return r.db.DB().Save(&session).Error
}

func (r *userSessionRepository) Delete(id string) error {
	return r.db.DB().Delete(&models.UserSession{}, "id = ?", id).Error
}

func (r *userSessionRepository) DeleteByToken(token string) error {
	return r.db.DB().Delete(&models.UserSession{}, "session_token = ?", token).Error
}

func (r *userSessionRepository) DeleteExpired() error {
	return r.db.DB().Delete(&models.UserSession{}, "expires_at <= CURRENT_TIMESTAMP").Error
}

func (r *userSessionRepository) DeleteUserSessions(userID string) error {
	return r.db.DB().Delete(&models.UserSession{}, "user_id = ?", userID).Error
}
