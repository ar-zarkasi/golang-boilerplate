package middlewares

import (
	"app/src/constants"
	"app/src/helpers"
	"app/src/services"
	"strings"

	"github.com/gin-gonic/gin"
)

type AuthenticationMiddleware interface {
	ValidatingToken() gin.HandlerFunc
	ValidateRefreshToken() gin.HandlerFunc
}

type authenticationMiddleware struct {
	helper helpers.HelperInterface
	auth   services.AuthorizationsService
}

func NewAuthMiddleware(authInterface services.AuthorizationsService) AuthenticationMiddleware {
	return &authenticationMiddleware{
		auth:   authInterface,
		helper: helpers.NewHelpers(),
	}
}

func (a *authenticationMiddleware) ValidatingToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			a.helper.ErrorResponse(c, constants.Forbidden, a.helper.ErrorMessage(constants.Forbidden))
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>" format
		if !strings.HasPrefix(authHeader, "Bearer ") {
			a.helper.ErrorResponse(c, constants.Forbidden, "Authorization header must start with Bearer")
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate the token
		verified, err := a.auth.VerifyToken(token)
		if err != nil {
			a.helper.ErrorResponse(c, constants.Unauthorized, a.helper.ErrorMessage(constants.Unauthorized))
			c.Abort()
			return
		}

		// Set user as active and store in context
		a.helper.SetUserActive(verified)
		a.helper.SetUserToken(token)
		c.Set("user", verified)
		c.Next()
	}
}

func (a *authenticationMiddleware) ValidateRefreshToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			a.helper.ErrorResponse(c, constants.Forbidden, a.helper.ErrorMessage(constants.Forbidden))
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>" format
		if !strings.HasPrefix(authHeader, "Bearer ") {
			a.helper.ErrorResponse(c, constants.Forbidden, "Authorization header must start with Bearer")
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate the refresh token
		valid, err := a.auth.VerifyRefreshToken(token)
		if err != nil {
			a.helper.ErrorResponse(c, constants.Unauthorized, a.helper.ErrorMessage(constants.Unauthorized))
			c.Abort()
			return
		}
		a.helper.SetTokenActive(token)
		a.helper.SetUserActive(valid)
		c.Set("user", valid)
		c.Next()
	}
}
