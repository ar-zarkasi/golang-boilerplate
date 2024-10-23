package middleware

import (
	"app/src/constant"
	"app/src/models"
	"app/src/services"
	"app/utils"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
)

var userActive *models.User

func AuthMiddleware(Users *services.UserService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		tokenHeader := ctx.GetHeader("Authorization")
		fmt.Println("TOKEN HEADER", tokenHeader)
		if tokenHeader == "" {
			code := constant.Unauthorized
			utils.ErrorResponse(ctx, code, utils.ErrorMessage(code))
			return
		}

		// extract token from header
		token := strings.TrimPrefix(tokenHeader, "Bearer ")
		if token == "" {
			code := constant.Forbidden
			utils.ErrorResponse(ctx, code, utils.ErrorMessage(code))
			return
		}

		fmt.Println("TOKEN HEADER LISTS", tokenHeader, token)

		// verify token
		user, err := Users.VerifyToken(token)
		fmt.Println("USER LISTED AUTHORIZE", user, err)
		if err != nil {
			code := constant.Unauthorized
			utils.ErrorResponse(ctx, code, utils.ErrorMessage(code))
			return
		}

		// get user detail
		userActive = user
		
		ctx.Next()
	}
}

func GetUserActive() *models.User {
	return userActive
}