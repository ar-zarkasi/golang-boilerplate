package repository

import (
	"app/src/constant"
	"app/src/http/response"
	interfaces "app/src/interface"
	"app/src/models"
	"database/sql"
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

type AuthRepository struct {
	Db *gorm.DB
}

func NewAuth(db *gorm.DB) (interfaces.AuthInterface) {
	return &AuthRepository{Db: db}
}

func (t *AuthRepository) loadEager() *gorm.DB {
	return t.Db.Preload("User").Preload("User.Role")
}

func (t *AuthRepository) FindToken(token string) (login models.Authentication, err error) {
	db := t.loadEager()
	err = db.First(&login, "token = ?", token).Error
	return login, err
}

func (t *AuthRepository) FindTokenByUserId(userId string) (login []models.Authentication, err error) {
	db := t.loadEager()
	err = db.Find(&login, "user_id = ?", userId).Error
	return login, err
}

func (t *AuthRepository) Signin(user models.User, token string, expired *time.Time, metadata *interface{}) (*response.TokenResponse, error) {
	jsonString, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}

	login := models.Authentication{
		UserId: user.Id,
		Token: token,
		ExpiredAt: sql.NullTime{Time: *expired, Valid: true},
		MetaData: sql.NullString{String: string(jsonString), Valid: true},
	}

	err = t.Db.Create(&login).Error
	if err != nil {
		return nil, err
	}

	resp := response.TokenResponse{
		UserId: login.UserId.String(),
		Token: login.Token,
		ExpiredAt: login.ExpiredAt.Time.Format(constant.FORMAT_DATETIME),
	}
	return &resp, err
}

func (t *AuthRepository) DeleteToken(login models.Authentication) error {
	return t.Db.Delete(&login).Error
}

func (t *AuthRepository) DeleteTokenByID(id ...uint64) error {
	db := t.Db.Where("id IN (?)", id)
	return db.Delete(&models.Authentication{}).Error
}
