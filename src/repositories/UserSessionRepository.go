package repository

import (
	"errors"

	"app/src/models"

	"gorm.io/gorm"
)

type UserSessionRepository interface {
	BaseRepository[models.UserSession]
	GetByID(ID string) (*models.UserSession, error)
	GetByToken(token string) (models.UserSession, error)
	GetByRefreshToken(refreshToken string) (models.UserSession, error)
	GetByUserID(userID string) ([]models.UserSession, error)
	DeleteByToken(token string) error
	DeleteExpired() error
	DeleteUserSessions(userID string) error
}

type userSessionRepository struct {
	BaseRepository[models.UserSession]
	db *gorm.DB
}

func NewUserSessionRepository(db *gorm.DB) UserSessionRepository {
	// Define the relationships to preload
	relation := []string{
		"User",
		"User.Profile",
		"User.UserRoles",
		"User.UserRoles.Role",
	}
	return &userSessionRepository{
		db:             db,
		BaseRepository: NewBaseRepository(db, models.UserSession{}, relation),
	}
}

func (r *userSessionRepository) GetByToken(token string) (models.UserSession, error) {
	var session models.UserSession
	if err := r.BaseQuery().Where("session_token = ? AND expires_at > CURRENT_TIMESTAMP", token).First(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.UserSession{}, nil
		}
		return models.UserSession{}, err
	}
	return session, nil
}

func (r *userSessionRepository) GetByRefreshToken(refreshToken string) (models.UserSession, error) {
	var session models.UserSession
	if err := r.BaseQuery().Where("refresh_token = ?", refreshToken).First(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.UserSession{}, nil
		}
		return models.UserSession{}, err
	}
	return session, nil
}

func (r *userSessionRepository) GetByID(ID string) (*models.UserSession, error) {
	var session models.UserSession
	if err := r.BaseQuery().Where("id = ?", ID).First(&session).Error; err != nil {
		return nil, err
	}
	return &session, nil
}

func (r *userSessionRepository) GetByUserID(userID string) ([]models.UserSession, error) {
	var session []models.UserSession
	if err := r.BaseQuery().Where("user_id = ? AND expires_at > CURRENT_TIMESTAMP", userID).Order("updated_at DESC").Find(&session).Error; err != nil {
		return nil, err
	}
	return session, nil
}

func (r *userSessionRepository) DeleteByToken(token string) error {
	return r.db.Delete(&models.UserSession{}, "session_token = ?", token).Error
}

func (r *userSessionRepository) DeleteExpired() error {
	return r.db.Delete(&models.UserSession{}, "expires_at <= CURRENT_TIMESTAMP").Error
}

func (r *userSessionRepository) DeleteUserSessions(userID string) error {
	return r.db.Delete(&models.UserSession{}, "user_id = ?", userID).Error
}
