package main

import (
	"app/router"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
)

func main() {
	port := ":"+os.Getenv("PORT")
	routers := router.GetRouter()

	mode := os.Getenv("GIN_MODE")
	allowed_url := []string{"*"}
	if mode == "release" {
		in_env_url := os.Getenv("ALLOWED_URL")
		if in_env_url != "" {
			// parsing to array string
			allowed_url = strings.Split(in_env_url, ",")
		}
	}
	// CORS configuration
    config := cors.Config{
        AllowOrigins:     allowed_url,
        AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "HEAD"},
        AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
        ExposeHeaders:    []string{"Content-Length"},
        AllowCredentials: true,
        MaxAge: 12 * time.Hour,
    }

    routers.Use(cors.New(config))
	routers.SetTrustedProxies(nil)
	err := routers.Run(port)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Server is running on port", port)
}