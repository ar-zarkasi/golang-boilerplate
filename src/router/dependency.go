package router

import (
	"app/src/controllers"
	"app/src/helpers"
	"app/src/middlewares"
	"app/src/services"
)

type DependenciesApp struct {
	Helper      helpers.HelperInterface
	AuthService services.AuthorizationsService
}

func NewDependenciesApp(helper helpers.HelperInterface) *DependenciesApp {
	return &DependenciesApp{
		Helper:      helper,
		AuthService: services.NewAuthorizationService(helper),
	}
}

// register controllers and middleware variable name here (CamelCase)
var (
	AuthController  *controllers.AuthController
	LoginMiddleware *middlewares.AuthenticationMiddleware
)

func (d *DependenciesApp) RegisterControllers() {
	// Register your controllers here
	AuthController = controllers.NewAuthController(d.Helper, d.AuthService)
}

func (d *DependenciesApp) RegisterMiddlewares() {
	// Register your middlewares here
	LoginMiddleware = middlewares.NewAuthMiddleware(d.Helper, d.AuthService)
}
