package controllers

import (
	"app/src/constants"
	"app/src/helpers"
	"app/src/services"
	"app/src/types"

	"github.com/gin-gonic/gin"
)

type AuthController struct {
	h           helpers.HelperInterface
	authService services.AuthorizationsService
}

func NewAuthController(auth services.AuthorizationsService) *AuthController {
	return &AuthController{
		authService: auth,
		h:           helpers.NewHelpers(),
	}
}

// SignIn godoc
// @Summary      User login
// @Description  Authenticate user with username and password
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request body types.LoginRequest true "Login credentials"
// @Success      200 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Login successful"
// @Failure      400 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Validation error"
// @Failure      401 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Invalid credentials"
// @Failure      500 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Internal server error"
// @Router       /auth/signin [post]
func (c *AuthController) SignIn(ctx *gin.Context) {
	var request types.LoginRequest
	if err := c.h.CheckValidationRequest(ctx, &request); err != nil {
		c.h.ErrorResponse(ctx, constants.ValidationError, c.h.ErrorMessage(constants.ValidationError))
		return
	}

	user, code, err := c.authService.Authorize(request.Username, request.Password)
	if err != nil {
		c.h.ErrorResponse(ctx, code, err.Error())
		return
	}

	response := types.ResponseDefault{
		Status:  true,
		Code:    code,
		Data:    user,
		Message: "Login successful",
	}
	c.h.SendResponse(ctx, response)
}

// SignUp godoc
// @Summary      User registration
// @Description  Register a new user account
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request body types.RegisterUserRequest true "User registration details"
// @Success      201 {object} types.ResponseDefault{status=bool,code=int,data=object{user_id=string},message=string} "User registered successfully"
// @Failure      400 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Validation error"
// @Failure      409 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "User already exists"
// @Failure      500 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Internal server error"
// @Router       /auth/signup [post]
func (c *AuthController) SignUp(ctx *gin.Context) {
	var userRequest types.RegisterUserRequest
	if err := c.h.CheckValidationRequest(ctx, &userRequest); err != nil {
		c.h.ErrorResponse(ctx, constants.ValidationError, c.h.ErrorMessage(constants.ValidationError))
		return
	}

	user, code, err := c.authService.RegisterUser(userRequest)
	if err != nil {
		c.h.ErrorResponse(ctx, code, err.Error())
		return
	}

	response := types.ResponseDefault{
		Status:  true,
		Code:    code,
		Data:    map[string]string{"user_id": user.ID},
		Message: "User registered successfully",
	}
	c.h.SendResponse(ctx, response)
}

// RefreshToken godoc
// @Summary      Refresh access token
// @Description  Refresh user's access token using refresh token
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Success      200 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Token refreshed successfully"
// @Failure      401 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Unauthorized - invalid or missing token"
// @Failure      500 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Internal server error"
// @Router       /auth/refresh [get]
func (c *AuthController) RefreshToken(ctx *gin.Context) {
	tokenrefresh := c.h.GetTokenActive()
	if tokenrefresh == "" {
		c.h.ErrorResponse(ctx, constants.Unauthorized, c.h.ErrorMessage(constants.Unauthorized))
		return
	}

	user := c.h.GetUserActive()
	loggedRefres, code, err := c.authService.RefreshToken(user.ID, tokenrefresh)
	if err != nil {
		c.h.ErrorResponse(ctx, code, err.Error())
		return
	}

	response := types.ResponseDefault{
		Status:  true,
		Code:    code,
		Data:    loggedRefres,
		Message: "Token refreshed successfully",
	}
	c.h.SendResponse(ctx, response)
}

// SignOut godoc
// @Summary      User logout
// @Description  Logout user and revoke authentication token
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Success      200 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Logout successful"
// @Failure      401 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Unauthorized - invalid or missing token"
// @Failure      500 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Internal server error"
// @Router       /auth/signout [get]
func (c *AuthController) SignOut(ctx *gin.Context) {
	token := c.h.GetUserToken()
	if token == "" {
		c.h.ErrorResponse(ctx, constants.Unauthorized, c.h.ErrorMessage(constants.Unauthorized))
		return
	}

	if err := c.authService.RevokeAuthorization(token); err != nil {
		c.h.ErrorResponse(ctx, constants.InternalServerError, err.Error())
		return
	}

	response := types.ResponseDefault{
		Status:  true,
		Code:    constants.Success,
		Data:    nil,
		Message: "Logout successful",
	}
	c.h.SendResponse(ctx, response)

}

// ListRoles godoc
// @Summary      List all roles
// @Description  Get a paginated list of all available roles
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        last_value query string false "Last cursor value for pagination"
// @Param        limit query int false "Number of items per page" default(10)
// @Param        query_string query string false "Search query string"
// @Param        sort_by query string false "Field to sort by"
// @Param        sort_order query string false "Sort order (asc/desc)" Enums(asc, desc)
// @Success      200 {object} types.ResponseDefault{status=bool,code=int,data=[]types.ListDataRoles,message=string} "Roles retrieved successfully"
// @Failure      401 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Unauthorized"
// @Failure      500 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Internal server error"
// @Router       /auth/roles [get]
func (c *AuthController) ListRoles(ctx *gin.Context) {
	var req types.PagingCursor
	// get query parameters from url
	ctx.BindQuery(&req)

	roles, err := c.authService.ListRoles(req)
	if err != nil {
		c.h.ErrorResponse(ctx, constants.InternalServerError, err.Error())
		return
	}

	response := types.ResponseDefault{
		Status:  true,
		Code:    constants.Success,
		Data:    roles,
		Message: "Roles retrieved successfully",
	}
	c.h.SendResponse(ctx, response)
}
