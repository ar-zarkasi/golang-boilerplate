package utils

import (
	"app/src/constant"

	"github.com/gin-gonic/gin"
)

func ErrorFatal(err error) {
	if err != nil {
		panic(err)
	}
}

func ErrorResponse(context *gin.Context, code int, message string) {
	Send(context, code, message)
}

func ErrorMessage(code int) string {
	errorMessages := map[int]string{
		constant.BadRequest:           "Bad Request",
		constant.Unauthorized:         "Unauthorized",
		constant.Forbidden:            "Forbidden",
		constant.NotFound:             "Not Found",
		constant.MethodNotAllowed:     "Method Not Allowed",
		constant.InternalServerError:  "Internal Server Error",
		constant.ServiceUnavailable:   "Service Unavailable",
		constant.GatewayTimeout:       "Gateway Timeout",
		constant.ServiceBroken:        "Service Not Completed",
	}
	return errorMessages[code]
}