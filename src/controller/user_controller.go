package controller

import (
	"app/src/constant"
	"app/src/http/request"
	"app/src/http/response"
	"app/src/services"
	"app/utils"
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

type UserController struct {
	UserService services.UserService
	Validate *validator.Validate
}

func NewUserController(UserService services.UserService, validate *validator.Validate) *UserController {
	if validate == nil {
		utils.ErrorFatal(errors.New("validator instance cannot be nil"))
	}
	return &UserController{UserService: UserService, Validate: validate}
}

func (controller *UserController) CreateUser(ctx *gin.Context) {
	req := request.CreateUserRequest{}
	ctx.ShouldBind(&req)

	err := controller.Validate.Struct(req)
	if err != nil {
		utils.ErrorResponse(ctx, constant.ValidationError, err.Error())
		return
	}

	req.Password, err = utils.HashPassword(req.Password)
	if err != nil {
		utils.ErrorResponse(ctx, constant.ServiceBroken, err.Error())
		return
	}

	id_new, code, err := controller.UserService.AddUser(req)
	if err != nil {
		utils.ErrorResponse(ctx, code, err.Error())
		return
	}

	resp := response.CreateUserResponse{
		ID: *id_new,
	}

	utils.Send(ctx, code, "User created successfully", resp)
}

func (controller *UserController) GetUsers(ctx *gin.Context) {
	users, err := controller.UserService.GetAllUser()
	if err != nil {
		utils.ErrorResponse(ctx, constant.InternalServerError, err.Error())
	}

	utils.Send(ctx, constant.Success, "Users retrieved successfully", users)
}

func (controller *UserController) UpdateUser(ctx *gin.Context) {
	id := ctx.Param("id")
	_, err := controller.UserService.GetUserById(id)
	if err != nil {
		utils.ErrorResponse(ctx, constant.InternalServerError, err.Error())
	}

	req := request.UpdateUserRequest{}
	ctx.ShouldBind(&req)
	err = controller.Validate.Struct(req)
	if err != nil {
		utils.ErrorResponse(ctx, constant.ValidationError, err.Error())
		return
	}

	code, err := controller.UserService.UpdateUser(id, req)
	if err != nil {
		utils.ErrorResponse(ctx, code, err.Error())
		return
	}

	utils.Send(ctx, code, "User retrieved successfully")
}

func (controller *UserController) DeleteUser(ctx *gin.Context) {
	id := ctx.Param("id")
	_, err := controller.UserService.GetUserById(id)
	if err != nil {
		utils.ErrorResponse(ctx, constant.NotFound, err.Error())
	}

	code, err := controller.UserService.DeleteUser(id)
	if err != nil {
		utils.ErrorResponse(ctx, code, err.Error())
		return
	}

	utils.Send(ctx, code, "User Deleted successfully")
}

func (controller *UserController) GetUserById(ctx *gin.Context) {
	id := ctx.Param("id")
	user, err := controller.UserService.GetUserById(id)
	if err != nil {
		utils.ErrorResponse(ctx, constant.InternalServerError, err.Error())
	}

	utils.Send(ctx, constant.Success, "User retrieved successfully", user)
}

func (controller *UserController) Login(ctx *gin.Context) {
	req := request.LoginRequest{}
	ctx.ShouldBind(&req)
	valid := controller.Validate.Struct(req)
	if valid != nil {
		utils.ErrorResponse(ctx, constant.ValidationError, valid.Error())
		return
	}
	metadata := req.Metadata
	login, code, err := controller.UserService.Login(req, metadata)
	if err != nil {
		utils.ErrorResponse(ctx, code, err.Error())
		return
	}

	utils.Send(ctx, code, "Login successfully", login)
}