package seeders

import (
	"app/src/models"
	"app/src/types"

	"gorm.io/gorm"
)

type RoleSeeder struct{}

func (s *RoleSeeder) GetName() string {
	return "RoleSeeder"
}

func (s *RoleSeeder) Seed(db *gorm.DB) error {
	roles := []models.Role{
		{
			Name:         "admin",
			Description:  "Administrator role with full permissions",
			IsSystemRole: true,
			Permissions: types.JSONB{
				"users":    []string{"create", "read", "update", "delete"},
				"roles":    []string{"create", "read", "update", "delete"},
				"settings": []string{"manage"},
			},
		},
		{
			Name:         "user",
			Description:  "Standard user role with basic permissions",
			IsSystemRole: true,
			Permissions: types.JSONB{
				"profile": []string{"read", "update"},
			},
		},
		{
			Name:         "moderator",
			Description:  "Moderator role with content management permissions",
			IsSystemRole: false,
			Permissions: types.JSONB{
				"users":   []string{"read"},
				"content": []string{"create", "read", "update", "delete"},
			},
		},
	}

	// Use FirstOrCreate to avoid duplicates
	for _, role := range roles {
		var existingRole models.Role
		if err := db.Where("name = ?", role.Name).First(&existingRole).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				// Role doesn't exist, create it
				if err := db.Create(&role).Error; err != nil {
					return err
				}
			} else {
				return err
			}
		}
	}

	return nil
}
