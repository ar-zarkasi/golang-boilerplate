package controller

import (
	"app/src/constant"
	"app/src/http/request"
	"app/src/http/response"
	"app/src/services"
	"app/utils"
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

type RoleController struct {
	Service services.RoleService
	Validator *validator.Validate
}

func NewRoleController(service services.RoleService, Validation *validator.Validate) *RoleController {
	if Validation == nil {
		utils.ErrorFatal(errors.New("validator instance cannot be nil"))
	}
	return &RoleController{Service: service, Validator: Validation}
}

func (controller *RoleController) GetAllRole(ctx *gin.Context) {
	roles, err := controller.Service.ListRole()
	if err != nil {
		utils.ErrorResponse(ctx, constant.InternalServerError, "Failed to retrieve roles")
		return
	}

	utils.Send(ctx, constant.Success, "Roles retrieved successfully", roles)
}

func (controller *RoleController) CreateRole(ctx *gin.Context) {
	req := request.CreateRoleRequest{}
	ctx.ShouldBind(&req)

	err := controller.Validator.Struct(req)
	if err != nil {
		utils.ErrorResponse(ctx, constant.ValidationError, err.Error())
		return
	}

	id_new, err := controller.Service.AddRole(req.Name)
	if err != nil {
		utils.ErrorResponse(ctx, constant.InternalServerError, err.Error())
		return
	}

	resp := response.ListRoleResponse{
		ID: *id_new,
		Name: req.Name,
	}

	utils.Send(ctx, constant.Success, "Role created successfully", resp)
}

func (controller *RoleController) UpdateRole(ctx *gin.Context) {
	req := request.CreateRoleRequest{}
	ctx.ShouldBind(&req)

	err := controller.Validator.Struct(req)
	if err != nil {
		utils.ErrorResponse(ctx, constant.ValidationError, err.Error())
		return
	}

	id := ctx.Param("id")
	idInt, err := strconv.Atoi(id)
	if err != nil {
		utils.ErrorResponse(ctx, constant.ValidationError, "Invalid role ID")
		return
	}
	role := controller.Service.GetRoleById(idInt)
	if role == nil {
		utils.ErrorResponse(ctx, constant.NotFound, "Role not found")
		return
	}
	err = controller.Service.EditRole(role, req.Name)
	if err != nil {
		utils.ErrorResponse(ctx, constant.InternalServerError, "Failed to update role")
		return
	}

	resp := response.ListRoleResponse{
		ID: int(role.Id),
		Name: req.Name,
	}

	utils.Send(ctx, constant.Success, "Role created successfully", resp)
}