package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserRole struct {
	ID         string    `gorm:"primaryKey;type:uuid"`
	UserID     string    `gorm:"not null;type:uuid"`
	RoleID     string    `gorm:"not null;type:uuid"`
	AssignedBy *string   `gorm:"type:uuid"`
	AssignedAt time.Time `gorm:"default:CURRENT_TIMESTAMP"`
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
