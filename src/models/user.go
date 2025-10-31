package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID              string     `gorm:"primaryKey;type:uuid"`
	Username        string     `gorm:"unique;not null;size:100"`
	Email           string     `gorm:"unique;size:250"`
	Phone           string     `gorm:"unique;size:23"`
	PasswordHash    string     `gorm:"not null;size:255"`
	IsActive        bool       `gorm:"default:true"`
	EmailVerified   bool       `gorm:"default:false"`
	EmailVerifiedAt *time.Time `gorm:"null"`
	LastLoginAt     *time.Time `gorm:"null"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DeletedAt       gorm.DeletedAt `gorm:"index"`

	// Relationships
	Profile   *UserProfile  `gorm:"foreignKey:UserID"`
	UserRoles []UserRole    `gorm:"foreignKey:UserID"`
	Sessions  []UserSession `gorm:"foreignKey:UserID"`
}

func (c *User) BeforeCreate(tx *gorm.DB) error {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	c.CreatedAt = time.Now()
	c.UpdatedAt = time.Now()
	return nil
}

func (c *User) BeforeUpdate(tx *gorm.DB) error {
	c.UpdatedAt = time.Now()
	return nil
}
