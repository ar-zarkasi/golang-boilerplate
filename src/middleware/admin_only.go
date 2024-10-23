package middleware

import (
	"app/src/constant"
	"app/src/services"
	"app/utils"

	"github.com/gin-gonic/gin"
)

func AdminOnly (UserService *services.UserService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		RoleAdminId := 1
		user := GetUserActive()
		if user.Role.Id != uint8(RoleAdminId) {
			utils.ErrorResponse(ctx, constant.Forbidden, "You are not authorized to access this resource")
			return
		}

		ctx.Next()
	}
}