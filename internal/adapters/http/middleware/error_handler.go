package middleware

import (
	"errors"
	"net/http"

	"github.com/Shyntr/shyntr/internal/adapters/http/response"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func ErrorHandlerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) == 0 {
			return
		}

		ginErr := c.Errors.Last()
		actualErr := ginErr.Err

		log := logger.FromGin(c).With(zap.Error(actualErr))
		var appErr *response.AppError
		if errors.As(actualErr, &appErr) {
			if appErr.StatusCode >= 500 {
				log.Error("Internal API Error",
					zap.Int("status_code", appErr.StatusCode),
					zap.String("user_message", appErr.UserMessage),
				)
			} else {
				log.Warn("Client API Error",
					zap.Int("status_code", appErr.StatusCode),
					zap.String("user_message", appErr.UserMessage),
				)
			}
			response.HandleManagementError(c, appErr.StatusCode, appErr.UserMessage, appErr.Err)
			return
		}
		log.Error("Unhandled Internal Server Error")
		response.HandleManagementError(c, http.StatusInternalServerError, "An unexpected internal error occurred", actualErr)
	}
}
