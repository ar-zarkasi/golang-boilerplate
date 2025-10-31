package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserSession struct {
	ID           string    `gorm:"primaryKey;type:uuid"`
	UserID       string    `gorm:"not null;type:uuid"`
	SessionToken string    `gorm:"unique;not null;size:255"`
	RefreshToken string    `gorm:"unique;size:255"`
	IPAddress    string    `gorm:"type:inet"`
	UserAgent    string    `gorm:"type:text"`
	ExpiresAt    time.Time `gorm:"not null"`
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
