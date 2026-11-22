package server

import (
	"errors"
	"net/http"

	"github.com/farshore07/gdou_helper_backend/internal/integration/jwxt"
	"github.com/gin-gonic/gin"
)

// APIError 表示带 HTTP 状态码和业务错误码的结构化错误。
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e APIError) Error() string {
	return e.Message
}

func ok(c *gin.Context, data any) {
	c.JSON(http.StatusOK, gin.H{
		"code":    "OK",
		"message": "ok",
		"data":    data,
	})
}

func fail(c *gin.Context, err error) {
	var apiErr APIError
	if errors.As(err, &apiErr) {
		c.JSON(apiErr.Status, gin.H{
			"code":    apiErr.Code,
			"message": apiErr.Message,
			"data":    nil,
		})
		return
	}
	_ = c.Error(err)
	c.JSON(http.StatusInternalServerError, gin.H{
		"code":    "INTERNAL_ERROR",
		"message": "服务器内部错误",
		"data":    nil,
	})
}

func badRequest(message string) APIError {
	return APIError{
		Status:  http.StatusBadRequest,
		Code:    "BAD_REQUEST",
		Message: message,
	}
}

func mapJWXTError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, jwxt.ErrSessionExpired) {
		return APIError{
			Status:  http.StatusUnauthorized,
			Code:    "SESSION_EXPIRED",
			Message: jwxt.ErrSessionExpired.Error(),
		}
	}
	if errors.Is(err, errTokenNotFound) {
		return APIError{
			Status:  http.StatusUnauthorized,
			Code:    "SESSION_EXPIRED",
			Message: err.Error(),
		}
	}
	if errors.Is(err, errStoreFull) {
		return APIError{
			Status:  http.StatusServiceUnavailable,
			Code:    "SERVER_BUSY",
			Message: err.Error(),
		}
	}

	var jwErr *jwxt.Error
	if errors.As(err, &jwErr) {
		switch jwErr.Kind {
		case jwxt.ErrorInvalidCredentials:
			return APIError{
				Status:  http.StatusUnauthorized,
				Code:    "JWXT_INVALID_CREDENTIALS",
				Message: jwErr.Error(),
			}
		case jwxt.ErrorSessionExpired:
			return APIError{
				Status:  http.StatusUnauthorized,
				Code:    "SESSION_EXPIRED",
				Message: jwErr.Error(),
			}
		case jwxt.ErrorVerificationFailed:
			return APIError{
				Status:  http.StatusUnprocessableEntity,
				Code:    "JWXT_VERIFICATION_FAILED",
				Message: jwErr.Error(),
			}
		case jwxt.ErrorUpstreamTimeout:
			return APIError{
				Status:  http.StatusGatewayTimeout,
				Code:    "JWXT_UPSTREAM_TIMEOUT",
				Message: jwErr.Error(),
			}
		default:
			return APIError{
				Status:  http.StatusBadGateway,
				Code:    "JWXT_UPSTREAM_ERROR",
				Message: jwErr.Error(),
			}
		}
	}
	return err
}
