package router

import (
	"app/src/constants"
	"app/src/controllers"
	"app/src/helpers"
	"app/src/middlewares"
	"app/src/services"
	"app/src/types"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func SetupRoutes() *gin.Engine {
	helper := helpers.NewHelpers()
	config := helper.GetMainConfig()
	// setup GIN & Cors
	routers := gin.Default()
	routers.SetTrustedProxies(nil)
	mode := os.Getenv("GIN_MODE")
	configCors := cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Realm"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	if mode == "release" {
		configCors.AllowAllOrigins = false
		configCors.AllowOrigins = strings.Split(config.Cors.AllowedUrl, ",")
	}

	routers.Use(cors.New(configCors))

	// Initialize services
	authService := services.NewAuthorizationService()
	// Initialize controllers
	authController := controllers.NewAuthController(authService)
	// Initialize middleware
	userLoggedIn := middlewares.NewAuthMiddleware(authService)

	routers.GET("/", func(c *gin.Context) {
		version := os.Getenv("VERSION")
		if version == "" {
			version = "1.0.0" // Default version if not set
		}
		response := types.ResponseDefault{
			Status: true,
			Code:   constants.Success,
			Data: map[string]string{
				"version": version,
			},
			Message: "Golang Boilerplate for Microservices",
		}
		helper.SendResponse(c, response)
	})
	routers.NoRoute(func(ctx *gin.Context) {
		helper.ErrorResponse(ctx, constants.NotFound, helper.ErrorMessage(constants.NotFound))
	})
	routers.GET("/documentation/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Auth routes
	v1router := routers.Group("/v1")
	{
		v1router.POST("/login", authController.SignIn)
		v1router.POST("/register", authController.SignUp)
		v1router.GET("/logout", authController.SignOut, userLoggedIn.ValidatingToken())
		v1router.GET("/refresh", authController.RefreshToken, userLoggedIn.ValidateRefreshToken())
		v1UserRouter := v1router.Group("/user")
		{
			v1UserRouter.GET("/roles", authController.ListRoles, userLoggedIn.ValidatingToken())
		}
	}

	return routers
}
