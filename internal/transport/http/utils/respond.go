package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func RespondError(c *gin.Context, status int, code, message string) {
	c.JSON(status, ErrorResponse{Error: code, Message: message})
}

func RespondOK(c *gin.Context, payload interface{}) {
	c.JSON(http.StatusOK, payload)
}

func RespondCreated(c *gin.Context, payload interface{}) {
	c.JSON(http.StatusCreated, payload)
}
