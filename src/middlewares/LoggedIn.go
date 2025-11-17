package middlewares

import (
	"app/src/constants"
	"app/src/helpers"
	"app/src/services"
	"log"
	"strings"

	"github.com/gin-gonic/gin"
)

type AuthenticationMiddleware struct {
	helper helpers.HelperInterface
	auth   services.AuthorizationsService
}

func NewAuthMiddleware(helper helpers.HelperInterface, authInterface services.AuthorizationsService) *AuthenticationMiddleware {
	return &AuthenticationMiddleware{
		helper: helper,
		auth:   authInterface,
	}
}

func (a *AuthenticationMiddleware) ValidatingToken() gin.HandlerFunc {
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
		c.Set("user", verified)
		c.Set("token", token)
		c.Set("session_id", sessionID)
		c.Next()
	}
}

func (a *AuthenticationMiddleware) ValidateRefreshToken() gin.HandlerFunc {
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
		log.Printf("Token Here: %s\n", token)
		// Validate the refresh token
		var sessionID string
		valid, err := a.auth.VerifyRefreshToken(token, &sessionID)
		if err != nil || sessionID == "" {
			a.helper.ErrorResponse(c, constants.Unauthorized, "Not authorized or invalid refresh token")
			c.Abort()
			return
		}
		c.Set("user", valid)
		c.Set("refreshToken", token)
		c.Set("session_id", sessionID)
		log.Printf("Refresh token validated for user: %s\n Token Is : %s", valid.Username, token)
		c.Next()
	}
}
