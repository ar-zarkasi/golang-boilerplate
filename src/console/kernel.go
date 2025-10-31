package console

import (
	"app/src/helpers"
	"fmt"
	"log"
	"os"
	"strings"
)

// Command interface that all console commands must implement
type Command interface {
	Name() string
	Description() string
	Execute(h helpers.HelperInterface, args []string) error
}

// Kernel manages all console commands
type Kernel struct {
	helper   helpers.HelperInterface
	commands map[string]Command
}

// NewKernel creates a new console kernel
func NewKernel(h helpers.HelperInterface) *Kernel {
	return &Kernel{
		helper:   h,
		commands: make(map[string]Command),
	}
}

// Register adds a command to the kernel
func (k *Kernel) Register(command Command) {
	k.commands[command.Name()] = command
}

// Run executes a command based on CLI arguments
func (k *Kernel) Run(args []string) {
	// If no arguments provided, show help
	if len(args) < 2 {
		k.ShowHelp()
		return
	}

	commandName := args[1]

	// Check for global help flag
	if commandName == "--help" || commandName == "-h" || commandName == "help" {
		k.ShowHelp()
		return
	}

	// Check for list command
	if commandName == "--list" || commandName == "list" {
		k.ListCommands()
		return
	}

	// Find and execute the command
	command, exists := k.commands[commandName]
	if !exists {
		fmt.Printf("Unknown command: %s\n", commandName)
		fmt.Println("\nRun 'go run main.go --help' to see available commands")
		os.Exit(1)
	}

	// Execute the command with remaining arguments
	commandArgs := []string{}
	if len(args) > 2 {
		commandArgs = args[2:]
	}

	if err := command.Execute(k.helper, commandArgs); err != nil {
		log.Fatalf("Command failed: %v", err)
	}
}

// ShowHelp displays available commands
func (k *Kernel) ShowHelp() {
	fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║           Go Boilerplate - Console Commands              ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println("\nUsage:")
	fmt.Println("  go run main.go [command] [options]")
	fmt.Println("\nAvailable Commands:")

	// Calculate max width for alignment
	maxWidth := 0
	for name := range k.commands {
		if len(name) > maxWidth {
			maxWidth = len(name)
		}
	}

	for name, cmd := range k.commands {
		padding := strings.Repeat(" ", maxWidth-len(name)+2)
		fmt.Printf("  %s%s%s\n", name, padding, cmd.Description())
	}

	fmt.Println("\nGlobal Options:")
	fmt.Println("  --help, -h           Show this help message")
	fmt.Println("  --list               List all available commands")
	fmt.Println("\nExamples:")
	fmt.Println("  go run main.go seed")
	fmt.Println("  go run main.go seed --class RoleSeeder")
	fmt.Println("  go run main.go --help")
	fmt.Println()
}

// ListCommands displays all registered commands
func (k *Kernel) ListCommands() {
	fmt.Println("\nRegistered Commands:")
	i := 1
	for name, cmd := range k.commands {
		fmt.Printf("%d. %s - %s\n", i, name, cmd.Description())
		i++
	}
	fmt.Println()
}
