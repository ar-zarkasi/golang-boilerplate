package commands

import (
	"app/database/seeders"
	"app/src/helpers"
	"fmt"
	"os"
)

// SeedCommand handles database seeding operations
type SeedCommand struct{}

func (c *SeedCommand) Name() string {
	return "seed"
}

func (c *SeedCommand) Description() string {
	return "Run database seeders"
}

func (c *SeedCommand) Execute(h helpers.HelperInterface, args []string) error {
	// Get database connection from the helper initialized in main
	db := h.GetDatabase()
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	// Create database seeder
	dbSeeder := seeders.NewDatabaseSeeder()

	// Parse command arguments
	if len(args) == 0 {
		// Run all seeders
		fmt.Println("Running all seeders...")
		if err := dbSeeder.Run(db.DB()); err != nil {
			return fmt.Errorf("seeding failed: %w", err)
		}
		return nil
	}

	// Handle specific commands
	command := args[0]

	switch command {
	case "--class":
		// Run specific seeder
		if len(args) < 2 {
			return fmt.Errorf("please specify a seeder class name. Example: go run main.go seed --class RoleSeeder")
		}
		seederName := args[1]
		fmt.Printf("Running seeder: %s\n", seederName)
		if err := dbSeeder.RunSpecific(db.DB(), seederName); err != nil {
			return fmt.Errorf("seeding failed: %w", err)
		}

	case "--list":
		// List all available seeders
		fmt.Println("Available seeders:")
		for i, name := range dbSeeder.List() {
			fmt.Printf("%d. %s\n", i+1, name)
		}

	case "--help", "-h":
		c.ShowHelp()

	default:
		fmt.Printf("Unknown option: %s\n", command)
		c.ShowHelp()
		os.Exit(1)
	}

	return nil
}

func (c *SeedCommand) ShowHelp() {
	fmt.Println("\nUsage:")
	fmt.Println("  go run main.go seed              - Run all seeders")
	fmt.Println("  go run main.go seed --class NAME - Run specific seeder")
	fmt.Println("  go run main.go seed --list       - List all available seeders")
	fmt.Println("  go run main.go seed --help       - Show this help message")
	fmt.Println("\nExamples:")
	fmt.Println("  go run main.go seed")
	fmt.Println("  go run main.go seed --class RoleSeeder")
	fmt.Println("  go run main.go seed --list")
}
