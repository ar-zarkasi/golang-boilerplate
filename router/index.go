package router

import (
	"app/config"
	"app/src/controller"
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

	// populate service
	UserService, err := services.NewUserService(UserRepository, RoleRepository)
	utils.ErrorFatal(err)
	UserService.CreateFirstUser()

	// populate controller handler
	groupApi := routerAPI.Group("/")
	userRouter(groupApi, validator, UserService)
}

func userRouter(router *gin.RouterGroup, validator *validator.Validate,UserService *services.UserService) {
	controller := controller.NewUserController(*UserService, validator)
	user_route := router.Group("/users")
		user_route.GET("", controller.GetUsers)
		user_route.POST("", controller.CreateUser)
	return
}

func GetRouter() *gin.Engine {
	return routerAPI
}