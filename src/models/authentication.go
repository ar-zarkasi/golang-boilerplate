package models

import (
	"database/sql"

	"github.com/google/uuid"
)

type Authentication struct {
	Id   uint64  `gorm:"primaryKey;autoIncrement" json:"id"`
	UserId uuid.UUID `gorm:"type:uuid" json:"user_id"`
	Token string `gorm:"type:varchar(255)" json:"token"`
	ExpiredAt uint32 `gorm:"autoCreateTime:nano" json:"expired_at"`
	MetaData sql.NullString `gorm:"type:json;nullable" json:"meta_data"`

	User User `gorm:"foreignKey:UserId;references:Id" json:"user"`
}