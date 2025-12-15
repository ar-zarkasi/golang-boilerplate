package middlewares

import (
	"app/src/constants"
	"app/src/helpers"
	"app/src/services"
	"strings"

	"github.com/gin-gonic/gin"
)

type AuthenticationOutMiddleware struct {
	helper helpers.HelperInterface
	auth   services.AuthorizationsService
}

func NewAuthOutMiddleware(helper helpers.HelperInterface, authInterface services.AuthorizationsService) *AuthenticationOutMiddleware {
	return &AuthenticationOutMiddleware{
		helper: helper,
		auth:   authInterface,
	}
}

func (a *AuthenticationOutMiddleware) ValidatingToken() gin.HandlerFunc {
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
		var sessionID string
		verified, err := a.auth.VerifyToken(token, &sessionID)
		if err != nil || sessionID == "" {
			a.helper.ErrorResponse(c, constants.Unauthorized, a.helper.ErrorMessage(constants.Unauthorized))
			c.Abort()
			return
		}

		// Set user as active and store in context
		a.helper.SetUserActive(*verified)
		c.Set("user", verified)
		c.Set("token", token)
		c.Set("session_id", sessionID)
		c.Next()
	}
}
