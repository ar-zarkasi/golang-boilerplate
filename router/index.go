package router

import (
	"app/config"
	"app/src/controller"
	"app/src/middleware"
	"app/src/repository"
	"app/src/services"
	"app/utils"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

var (
	service = gin.Default()
	routerAPI *gin.Engine
)

func init() {
	db := config.GetActiveDB()
	validator := config.GetValidator()
	routerAPI = gin.Default()

	// populate repository
	RoleRepository := repository.NewRole(db)
	UserRepository := repository.NewUser(db)
	AuthRepository := repository.NewAuth(db)

	// populate service
	RoleService, err := services.NewRoleService(RoleRepository)
	utils.ErrorFatal(err)
	_, err = RoleService.CreateAdminRole()
	utils.ErrorFatal(err)

	UserService, err := services.NewUserService(UserRepository, RoleRepository, &AuthRepository)
	utils.ErrorFatal(err)
	UserService.CreateFirstUser()

	// Middleware
	authMiddleware := middleware.AuthMiddleware(UserService)
	adminOnlyMiddleware := middleware.AdminOnly(UserService)

	// populate controller handler
	groupApi := routerAPI.Group("/")
	authRouter(groupApi, validator, *UserService, authMiddleware)
	userRouter(groupApi, validator, *UserService, &authMiddleware)
	roleRouter(groupApi, validator, *RoleService, &authMiddleware, &adminOnlyMiddleware)
}

func authRouter(router *gin.RouterGroup, validator *validator.Validate, Service services.UserService, AuthMiddleware gin.HandlerFunc) {
	controller := controller.NewUserController(Service, validator)
	router.POST("/login", controller.Login)
	router.POST("/logout", nil, AuthMiddleware)
}

func userRouter(router *gin.RouterGroup, validator *validator.Validate, Service services.UserService, middleware ...*gin.HandlerFunc) {
	controller := controller.NewUserController(Service, validator)
	user_route := router.Group("/users", *middleware[0])
		user_route.GET("", controller.GetUsers)
		user_route.POST("", controller.CreateUser)
		user_route.GET("/:id", controller.GetUserById)
		user_route.PUT("/:id", controller.UpdateUser)
		user_route.DELETE("/:id", controller.DeleteUser)
	return
}

func roleRouter(router *gin.RouterGroup, validator *validator.Validate,Service services.RoleService, middleware ...*gin.HandlerFunc) {
	controller := controller.NewRoleController(Service, validator)
	role_route := router.Group("/roles")
		role_route.GET("", controller.GetAllRole)
		sub_role_route := role_route.Group("", *middleware[0])
			sub_role_route.POST("", controller.CreateRole, *middleware[1])
		role_route.PUT("/:id", controller.UpdateRole)
	return
}

func GetRouter() *gin.Engine {
	return routerAPI
}