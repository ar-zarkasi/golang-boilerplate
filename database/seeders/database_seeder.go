package seeders

import (
	"app/database"

	"gorm.io/gorm"
)

// DatabaseSeeder is the main seeder that orchestrates all other seeders
type DatabaseSeeder struct {
	registry *database.SeederRegistry
}

// NewDatabaseSeeder creates a new database seeder with all seeders registered
func NewDatabaseSeeder() *DatabaseSeeder {
	registry := database.NewSeederRegistry()

	// Register all seeders in order
	// The order matters! For example, roles must be seeded before user_roles
	registry.Register(&RoleSeeder{})
	// Add other seeders here
	// registry.Register(&UserSeeder{})
	// registry.Register(&PostSeeder{})

	return &DatabaseSeeder{
		registry: registry,
	}
}

// Run executes all seeders
func (ds *DatabaseSeeder) Run(db *gorm.DB) error {
	return ds.registry.Run(db)
}

// RunSpecific executes a specific seeder by name
func (ds *DatabaseSeeder) RunSpecific(db *gorm.DB, name string) error {
	return ds.registry.RunSpecific(db, name)
}

// List returns all registered seeder names
func (ds *DatabaseSeeder) List() []string {
	return ds.registry.List()
}
