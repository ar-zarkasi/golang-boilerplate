package models

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	Id	      uuid.UUID  `gorm:"type:uuid;primaryKey;" json:"id"`
    Name      string  `gorm:"type:varchar(255)" json:"name"`
    Email     string  `gorm:"type:varchar(160);unique;uniqueIndex" json:"email"`
	Phone     string  `gorm:"type:varchar(15);unique;uniqueIndex" json:"phone"`
    Password  string  `gorm:"type:varchar(255)" json:"password"`
	RoleId	  uint8   `json:"role_id"`
	RefreshToken sql.NullString `gorm:"type:varchar(255);nullable;" json:"refresh_token"`
	RefreshTokenExpiredAt sql.NullTime `json:"refresh_token_expired_at"`
	CreatedAt time.Time  `gorm:"autoCreateTime:nano" json:"created_at"`
	UpdatedAt time.Time  `gorm:"autoCreateTime:nano;autoUpdateTime:nano" json:"updated_at"`
	DeletedAt sql.NullTime `json:"deleted_at"`
	
	Role Role `gorm:"foreignKey:RoleId;references:Id" json:"role"`
	Login []Authentication `gorm:"foreignKey:UserId;references:Id" json:"login"`
}

func (user *User) BeforeCreate(tx *gorm.DB) (err error) {
	newUID := uuid.New()
	user.Id = newUID
    return nil
}