package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserProfile struct {
	ID        string  `gorm:"primaryKey;type:char(36)"`
	UserID    string  `gorm:"unique;not null;type:char(36)"`
	FirstName string  `gorm:"size:100"`
	LastName  string  `gorm:"size:100"`
	AvatarURL *string `gorm:"null;type:text"`
	Timezone  string  `gorm:"default:'UTC';size:100"`
	Language  string  `gorm:"default:'en';size:10"`
	CreatedAt time.Time
	UpdatedAt time.Time

	// Relationships
	User User `gorm:"foreignKey:UserID"`
}

func (c *UserProfile) BeforeCreate(tx *gorm.DB) error {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	c.CreatedAt = time.Now()
	c.UpdatedAt = c.CreatedAt
	return nil
}

func (c *UserProfile) BeforeUpdate(tx *gorm.DB) error {
	c.UpdatedAt = time.Now()
	return nil
}
