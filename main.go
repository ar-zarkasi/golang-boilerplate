// Package main Golang Boilerplate
//
// This is the Golang Boilerplate for Microservices.
//
//	Title: Golang Boilerplate
//	Description: use it to start your next microservice project
//	Version: 1.0.0
//
// @contact.name   API Support
// @contact.email  arfan.zarkasi@gmail.com
// @license.name  MIT
// @license.url   https://opensource.org/licenses/MIT
// @Host: localhost:5000
// @BasePath: /
// @Schemes: http, https
//
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.
package main

import (
	"app/docs"
	"app/src/console"
	"app/src/helpers"
	"app/src/router"
	"log"
	"os"
)

func main() {
	// initialize the application
	h := helpers.NewHelpers()
	if err := h.InitializeSystem(); err != nil {
		h.ErrorFatal(err)
		return
	}
	h.SetupLogging()

	// Check if running as console command
	// Only treat as console command if there are args and they're not just the binary name
	if len(os.Args) > 1 && !isWebServerMode(os.Args[1], h) {
		// Setup and run console commands
		kernel := console.RegisterCommands(h)
		kernel.Run(os.Args)
		return
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "5000" // Default port if not set
	}

	// Start the server
	mainRouter := router.SetupRoutes(h)
	host := os.Getenv("HOST")
	if host == "" {
		host = "localhost:" + port
	}

	docs.SwaggerInfo.Host = host
	log.Printf("Server running on 0.0.0.0:%s", port)
	log.Printf("Accessible at: http://%s", host)

	// Bind to 0.0.0.0 to accept connections from outside the container
	err := mainRouter.Run("0.0.0.0:" + port)
	if err != nil {
		log.Fatal(err)
	}
}

// isWebServerMode checks if we should start in web server mode
// Returns true if the argument looks like it's not a console command
func isWebServerMode(arg string, h helpers.HelperInterface) bool {
	// If it ends with .go, it's from hot reload tools like gin/air
	if len(arg) >= 3 && arg[len(arg)-3:] == ".go" {
		return true
	}

	// These patterns indicate web server mode, not console commands
	webServerPatterns := []string{
		// When running with air or other hot reload tools
		"tmp/",
		".exe",
		"/tmp/",
		// When the binary is built and run directly
		"main",
		"app",
	}

	for _, pattern := range webServerPatterns {
		if len(arg) >= len(pattern) && arg[len(arg)-len(pattern):] == pattern {
			return true
		}
		if len(arg) >= len(pattern) && arg[:len(pattern)] == pattern {
			return true
		}
	}

	// If it starts with a dash, it's likely a help flag for console
	if len(arg) > 0 && arg[0] == '-' {
		return false
	}

	// Check if it's a known command by seeing if it contains path separators
	// If it has path separators, it's likely a binary path (web server mode)
	if len(arg) > 0 && (arg[0] == '/' || arg[0] == '.' || h.ContainString(arg, "/") || h.ContainString(arg, "\\")) {
		return true
	}

	return false
}
