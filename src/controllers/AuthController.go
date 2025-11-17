package controllers

import (
	"app/src/constants"
	"app/src/helpers"
	"app/src/models"
	"app/src/services"
	"app/src/types"

	"github.com/gin-gonic/gin"
)

type AuthController struct {
	helper      helpers.HelperInterface
	authService services.AuthorizationsService
}

func NewAuthController(h helpers.HelperInterface, auth services.AuthorizationsService) *AuthController {
	return &AuthController{
		helper:      h,
		authService: auth,
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
	if err := ctx.ShouldBindJSON(&request); err != nil {
		c.helper.ErrorResponse(ctx, constants.ValidationError, c.helper.FormatValidationError(err))
		return
	}

	user, code, err := c.authService.Authorize(request.Username, request.Password)
	if err != nil {
		c.helper.ErrorResponse(ctx, code, err.Error())
		return
	}

	response := types.ResponseDefault{
		Status:  true,
		Code:    code,
		Data:    user,
		Message: "Login successful",
	}
	c.helper.SendResponse(ctx, response)
}

// SignUp godoc
// @Summary      Register a new user
// @Description  Create a new user account with email or phone number
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request body types.RegisterUserRequest true "User registration data"
// @Success      201 {object} types.ResponseDefault{status=bool,code=int,data=object{user_id=string},message=string} "User registered successfully"
// @Failure      400 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Validation error"
// @Failure      409 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "User already exists"
// @Failure      500 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Internal server error"
// @Router       /auth/register [post]
func (c *AuthController) SignUp(ctx *gin.Context) {
	var userRequest types.RegisterUserRequest
	if err := ctx.ShouldBindJSON(&userRequest); err != nil {
		c.helper.ErrorResponse(ctx, constants.ValidationError, c.helper.FormatValidationError(err))
		return
	}

	user, code, err := c.authService.RegisterUser(userRequest)
	if err != nil {
		c.helper.ErrorResponse(ctx, code, err.Error())
		return
	}

	response := types.ResponseDefault{
		Status:  true,
		Code:    code,
		Data:    map[string]string{"user_id": user.ID},
		Message: "User registered successfully",
	}
	c.helper.SendResponse(ctx, response)
}

// RefreshToken godoc
// @Summary      Refresh access token
// @Description  Refresh user's access token using refresh token
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        Authorization header string true "Refresh Token" default(Bearer your_refresh_token_here)
// @Success      200 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Token refreshed successfully"
// @Failure      401 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Unauthorized - invalid or missing token"
// @Failure      500 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Internal server error"
// @Router       /auth/refresh [get]
func (c *AuthController) RefreshToken(ctx *gin.Context) {
	sessionID, ok := ctx.Get("session_id")
	if !ok {
		c.helper.ErrorResponse(ctx, constants.Unauthorized, c.helper.ErrorMessage(constants.Unauthorized))
		return
	}

	if err := c.authService.RevokeAuthorization(sessionID.(string)); err != nil {
		c.helper.ErrorResponse(ctx, constants.BadRequest, err.Error())
		return
	}

	var (
		loginUser types.UserAuth
		userModel models.User
	)
	userdata, ok := ctx.Get("user")
	if !ok {
		c.helper.ErrorResponse(ctx, constants.Forbidden, c.helper.ErrorMessage(constants.Forbidden))
		return
	}
	err := c.helper.InterfaceToStruct(userdata, &userModel)
	if err != nil {
		c.helper.ErrorResponse(ctx, constants.InternalServerError, err.Error())
		return
	}
	err = c.authService.Login(userModel, &loginUser)
	if err != nil {
		c.helper.ErrorResponse(ctx, constants.BadRequest, err.Error())
		return
	}

	response := types.ResponseDefault{
		Status:  true,
		Code:    constants.Success,
		Data:    loginUser,
		Message: "Token refreshed successfully",
	}
	c.helper.SendResponse(ctx, response)
}

// SignOut godoc
// @Summary      User logout
// @Description  Logout user and revoke authentication token
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Success      200 {object} types.ResponseDefault{status=bool,code=int,data=nil,message=string} "Logout successful"
// @Failure      401 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Unauthorized - invalid or missing token"
// @Failure      500 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Internal server error"
// @Router       /auth/signout [get]
func (c *AuthController) SignOut(ctx *gin.Context) {
	sessionID, ok := ctx.Get("session_id")
	if !ok {
		c.helper.ErrorResponse(ctx, constants.Unauthorized, c.helper.ErrorMessage(constants.Unauthorized))
		return
	}

	if err := c.authService.RevokeAuthorization(sessionID.(string)); err != nil {
		c.helper.ErrorResponse(ctx, constants.InternalServerError, err.Error())
		return
	}

	response := types.ResponseDefault{
		Status:  true,
		Code:    constants.Success,
		Data:    nil,
		Message: "Logout successful",
	}
	c.helper.SendResponse(ctx, response)

}

// ListRoles godoc
// @Summary      List all roles
// @Description  Get a paginated list of all available roles. Filter query format: [{"column":"name","operand":"like","value":"admin"}]. See types.FilterQuery model for structure.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        last_value query string false "Last cursor value for pagination"
// @Param        limit query int false "Number of items per page" default(10)
// @Param        query_string query string false "JSON array of filter objects (see types.FilterQuery). Example: [{'column':'name','operand':'like','value':'admin'}]"
// @Param        sort_by query string false "Field to sort by default to 'created_at'"
// @Param        sort_order query string false "Sort order (asc/desc)" Enums(asc, desc)
// @Success      200 {object} types.ResponseDefault{status=bool,code=int,data=[]types.ListDataRoles,message=string} "Roles retrieved successfully"
// @Failure      401 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Unauthorized"
// @Failure      500 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Internal server error"
// @Router       /users/roles [get]
func (c *AuthController) ListRoles(ctx *gin.Context) {
	var req types.PagingCursor
	// get query parameters from url
	if err := ctx.ShouldBindQuery(&req); err != nil {
		c.helper.ErrorResponse(ctx, constants.ValidationError, c.helper.FormatValidationError(err))
		return
	}

	// Parse query_string if present
	if queryStringParam := ctx.Query("query_string"); queryStringParam != "" {
		var filters []types.FilterQuery
		if err := c.helper.JSONToStruct([]byte(queryStringParam), &filters); err != nil {
			c.helper.ErrorResponse(ctx, constants.ValidationError, "Invalid query_string format: "+err.Error())
			return
		}
		req.QueryString = filters
	}

	if req.Limit == 0 {
		req.Limit = c.helper.GetDefaultLimitData()
	}
	user, ok := ctx.Get("user")
	if !ok {
		c.helper.ErrorResponse(ctx, constants.Forbidden, c.helper.ErrorMessage(constants.Forbidden))
		return
	}
	userModel := models.User{}
	err := c.helper.InterfaceToStruct(user, &userModel)
	if err != nil {
		c.helper.ErrorResponse(ctx, constants.InternalServerError, err.Error())
		return
	}

	roles, err := c.authService.ListRoles(req, userModel)
	if err != nil {
		c.helper.ErrorResponse(ctx, constants.InternalServerError, err.Error())
		return
	}

	response := types.ResponseDefault{
		Status:  true,
		Code:    constants.Success,
		Data:    roles,
		Message: "Roles retrieved successfully",
	}
	c.helper.SendResponse(ctx, response)
}

// CheckHasAdministrator godoc
// @Summary      Check if administrator exists
// @Description  Check whether the application has an administrator account configured
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Success      200 {object} types.ResponseDefault{status=bool,code=int,data=object{has_administrator=bool},message=string} "Check completed successfully"
// @Failure      500 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Internal server error"
// @Router       /check-setup [get]
func (c *AuthController) CheckHasAdministrator(ctx *gin.Context) {
	rdata := map[string]interface{}{
		"has_administrator": c.authService.AppHasAdministrator(),
	}
	c.helper.SendResponseData(ctx, constants.Success, "Checked Received", rdata)
}

// CreateAdministrator godoc
// @Summary      Create administrator account
// @Description  Create the initial administrator account for the application (only works if no administrator exists)
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request body types.RegisterAdministratorRequest true "Administrator registration details"
// @Success      201 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Administrator account created successfully"
// @Failure      400 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Bad request - administrator already exists"
// @Failure      422 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Validation error"
// @Failure      500 {object} types.ResponseDefault{status=bool,code=int,data=object,message=string} "Internal server error"
// @Router       /create-administrator [post]
func (c *AuthController) CreateAdministrator(ctx *gin.Context) {

	pass := c.authService.AppHasAdministrator()
	if pass {
		c.helper.ErrorResponse(ctx, constants.BadRequest, c.helper.ErrorMessage(constants.BadRequest))
		return
	}

	var request types.RegisterAdministratorRequest
	if err := ctx.ShouldBindJSON(&request); err != nil {
		c.helper.ErrorResponse(ctx, constants.ValidationError, c.helper.FormatValidationError(err))
		return
	}

	// Create administrator account
	_, code, err := c.authService.CreateAdminUser(request.Email, request.Password)
	if err != nil {
		c.helper.ErrorResponse(ctx, code, err.Error())
		return
	}

	c.helper.SendResponseData(ctx, code, "Administrator account created successfully", nil)
}
