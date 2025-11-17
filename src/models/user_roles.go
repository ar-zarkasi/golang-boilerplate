package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserRole struct {
	ID         string    `gorm:"primaryKey;type:char(36)"`
	UserID     string    `gorm:"not null;type:char(36)"`
	RoleID     string    `gorm:"not null;type:char(36)"`
	AssignedBy *string   `gorm:"null;type:char(36)"`
	AssignedAt time.Time `gorm:"autoCreateTime"`
	ExpiresAt  *time.Time

	// Relationships
	User           User  `gorm:"foreignKey:UserID"`
	Role           Role  `gorm:"foreignKey:RoleID"`
	AssignedByUser *User `gorm:"foreignKey:AssignedBy"`
}

func (c *UserRole) BeforeCreate(tx *gorm.DB) error {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	return nil
}
