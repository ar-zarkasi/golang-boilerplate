package router

import (
	"app/src/helpers"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func SetupRoutes(helper helpers.HelperInterface) *gin.Engine {
	config := helper.GetMainConfig()
	// setup GIN & Cors
	routers := gin.Default()
	routers.SetTrustedProxies(nil)
	configCors := cors.Config{
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Realm"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	if helper.IsProduction() {
		configCors.AllowOrigins = strings.Split(config.Cors.AllowedUrl, ",")
	} else {
		// In development, allow common localhost ports for Podman/Docker
		configCors.AllowOrigins = []string{
			"http://localhost",
			"http://localhost:7007",
			"http://localhost:5000",
			"http://localhost:3000",
			"http://127.0.0.1",
			"http://127.0.0.1:7007",
			"http://127.0.0.1:5000",
			"http://127.0.0.1:3000",
		}
	}

	routers.Use(cors.New(configCors))

	// Add request timeout middleware (30 seconds)
	routers.Use(func(c *gin.Context) {
		// Set a reasonable read timeout for the request body
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 10*1024*1024) // 10MB max
		c.Next()
	})

	// Initialize dependencies
	dep := NewDependenciesApp(helper)
	dep.RegisterControllers()
	dep.RegisterMiddlewares()

	r := NewApiRouter(helper, routers)
	routers = r.RegisterRoutes()

	return routers
}
