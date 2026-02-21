package middleware

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/internal/api/response"
)

func ErrorHandlerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) == 0 {
			return
		}

		ginErr := c.Errors.Last()
		actualErr := ginErr.Err

		var appErr *response.AppError
		if errors.As(actualErr, &appErr) {
			response.HandleManagementError(c, appErr.StatusCode, appErr.UserMessage, appErr.Err)
			return
		}
		response.HandleManagementError(c, http.StatusInternalServerError, "An unexpected internal error occurred", actualErr)
	}
}
