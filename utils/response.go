package utils

import (
	"github.com/gin-gonic/gin"
)

type response struct {
	Code  		int		 	`json:"code"`
	Message 	string 		`json:"message"`
	Data 		interface{} `json:"data,omitempty"`
}

type MessagesOnly struct {
	Messages string `json:"message"`
}

func Send(ctx *gin.Context, code int, message string, data ...interface{}) {
	ctx.JSON(code, response{
		Code: code,
		Message: message,
		Data: data,
	})
}