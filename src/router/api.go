package router

import (
	"app/src/constants"
	"app/src/helpers"
	"app/src/types"
	"os"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

type ApiRouter struct {
	Helper  helpers.HelperInterface
	Routers *gin.Engine
}

func NewApiRouter(helper helpers.HelperInterface, ginEngine *gin.Engine) *ApiRouter {
	return &ApiRouter{
		Helper:  helper,
		Routers: ginEngine,
	}
}
func (r *ApiRouter) RegisterRoutes() *gin.Engine {
	routers := r.Routers
	// Register your API routes here
	routers.GET("/", func(c *gin.Context) {
		version := os.Getenv("VERSION")
		if version == "" {
			version = "0.0.1" // Default version if not set
		}
		response := types.ResponseDefault{
			Status: true,
			Code:   constants.Success,
			Data: map[string]string{
				"version": version,
			},
			Message: "Authentication Service is running",
		}
		r.Helper.SendResponse(c, response)
	})
	routers.NoRoute(func(ctx *gin.Context) {
		r.Helper.ErrorResponse(ctx, constants.NotFound, r.Helper.ErrorMessage(constants.NotFound))
	})

	routers.GET("/check-setup", AuthController.CheckHasAdministrator)
	routers.POST("/create-administrator", AuthController.CreateAdministrator)
	authGroup := routers.Group("/auth")
	{
		authGroup.POST("/signin", AuthController.SignIn)
		authGroup.POST("/register", AuthController.SignUp)
		authGroup.GET("/refresh", LoginMiddleware.ValidateRefreshToken(), AuthController.RefreshToken)
		authGroup.GET("/signout", LoginMiddleware.ValidatingToken(), AuthController.SignOut)
	}

	v1UserRouter := routers.Group("/users", LoginMiddleware.ValidatingToken())
	{
		v1UserRouter.GET("/roles", AuthController.ListRoles)
	}

	routers.GET("/documentation/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	return routers
}
