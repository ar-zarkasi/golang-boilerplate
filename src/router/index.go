package router

import (
	"app/src/constants"
	"app/src/helpers"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
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
	configCors.AllowOrigins = strings.Split(config.Cors.AllowedUrl, ",")

	routers.Use(cors.New(configCors))

	// Add request timeout middleware (30 seconds)
	routers.Use(func(c *gin.Context) {
		// Set a reasonable read timeout for the request body
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 10*1024*1024) // 10MB max
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(constants.SuccessNoContent)
			return
		}
		c.Next()
	})
	//  adjust rate limiter
	routers.Use(func(c *gin.Context) {
		limiter := rate.NewLimiter(1, config.Cors.RateLimit)
		if !limiter.Allow() {
			helper.ErrorResponse(c, constants.TooManyRequest, "Too Many Request")
			return
		}

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
