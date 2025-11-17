package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserSession struct {
	ID           string    `gorm:"primaryKey;type:char(36)"`
	UserID       string    `gorm:"not null;type:char(36);index"`
	SessionToken string    `gorm:"unique;not null;type:varchar(512)"`
	RefreshToken string    `gorm:"unique;not null;type:varchar(255)"`
	IPAddress    *string   `gorm:"type:varchar(45);default:null"`
	UserAgent    *string   `gorm:"type:text"`
	ExpiresAt    time.Time `gorm:"not null;index"`
	CreatedAt    time.Time
	UpdatedAt    time.Time

	// Relationships
	User User `gorm:"foreignKey:UserID"`
}

func (c *UserSession) BeforeCreate(tx *gorm.DB) error {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	c.CreatedAt = time.Now()
	c.UpdatedAt = c.CreatedAt
	return nil
}

func (c *UserSession) BeforeUpdate(tx *gorm.DB) error {
	c.UpdatedAt = time.Now()
	return nil
}
