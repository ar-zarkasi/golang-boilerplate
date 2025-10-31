package database

import (
	"fmt"
	"log"

	"gorm.io/gorm"
)

// Seeder interface that all seeders must implement
type Seeder interface {
	Seed(db *gorm.DB) error
	GetName() string
}

// SeederRegistry holds all registered seeders
type SeederRegistry struct {
	seeders []Seeder
}

// NewSeederRegistry creates a new seeder registry
func NewSeederRegistry() *SeederRegistry {
	return &SeederRegistry{
		seeders: make([]Seeder, 0),
	}
}

// Register adds a seeder to the registry
func (r *SeederRegistry) Register(seeder Seeder) {
	r.seeders = append(r.seeders, seeder)
}

// Run executes all registered seeders
func (r *SeederRegistry) Run(db *gorm.DB) error {
	log.Println("Starting database seeding...")

	for _, seeder := range r.seeders {
		log.Printf("Seeding: %s", seeder.GetName())
		if err := seeder.Seed(db); err != nil {
			return fmt.Errorf("failed to run seeder %s: %w", seeder.GetName(), err)
		}
		log.Printf("✓ Completed: %s", seeder.GetName())
	}

	log.Println("Database seeding completed successfully!")
	return nil
}

// RunSpecific executes a specific seeder by name
func (r *SeederRegistry) RunSpecific(db *gorm.DB, name string) error {
	for _, seeder := range r.seeders {
		if seeder.GetName() == name {
			log.Printf("Seeding: %s", seeder.GetName())
			if err := seeder.Seed(db); err != nil {
				return fmt.Errorf("failed to run seeder %s: %w", seeder.GetName(), err)
			}
			log.Printf("✓ Completed: %s", seeder.GetName())
			return nil
		}
	}
	return fmt.Errorf("seeder not found: %s", name)
}

// List returns all registered seeder names
func (r *SeederRegistry) List() []string {
	names := make([]string, len(r.seeders))
	for i, seeder := range r.seeders {
		names[i] = seeder.GetName()
	}
	return names
}
