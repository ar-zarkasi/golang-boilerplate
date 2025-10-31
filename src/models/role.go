package models

import (
	"time"

	"app/src/types"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Role struct {
	ID           string      `gorm:"primaryKey;type:uuid"`
	Name         string      `gorm:"not null;size:100"`
	Description  string      `gorm:"type:text"`
	IsSystemRole bool        `gorm:"default:false"`
	Permissions  types.JSONB `gorm:"type:jsonb"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt `gorm:"index"`

	// Relationships
	UserRoles []UserRole `gorm:"foreignKey:RoleID"`
}

func (c *Role) BeforeCreate(tx *gorm.DB) error {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	c.CreatedAt = time.Now()
	c.UpdatedAt = c.CreatedAt
	return nil
}

func (c *Role) BeforeUpdate(tx *gorm.DB) error {
	c.UpdatedAt = time.Now()
	return nil
}
