package console

import (
	"app/src/console/commands"
	"app/src/helpers"
)

// RegisterCommands registers all available console commands
func RegisterCommands(h helpers.HelperInterface) *Kernel {
	kernel := NewKernel(h)

	// Register all console commands here
	kernel.Register(&commands.SeedCommand{})

	// Add more commands here in the future
	// kernel.Register(&commands.MigrateCommand{})
	// kernel.Register(&commands.CacheCommand{})
	// kernel.Register(&commands.QueueCommand{})

	return kernel
}
