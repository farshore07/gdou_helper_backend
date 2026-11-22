package jwxt

import (
	"context"
	"errors"
	"net"
)

// ErrSessionExpired 表示教务系统 Cookie 会话已失效，客户端需重新登录。
var ErrSessionExpired = errors.New("教务系统会话已过期，请重新登录")

// ErrorKind 区分认证和上游调用错误类别，便于 HTTP 层映射准确状态码。
type ErrorKind string

const (
	ErrorInvalidCredentials ErrorKind = "invalid_credentials"
	ErrorVerificationFailed ErrorKind = "verification_failed"
	ErrorSessionExpired     ErrorKind = "session_expired"
	ErrorUpstreamTimeout    ErrorKind = "upstream_timeout"
	ErrorUpstreamError      ErrorKind = "upstream_error"
)

// Error 表示带分类信息的教务集成错误。
type Error struct {
	Kind    ErrorKind
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return string(e.Kind)
}

func (e *Error) Unwrap() error {
	return e.Err
}

func newError(kind ErrorKind, message string, err error) *Error {
	return &Error{Kind: kind, Message: message, Err: err}
}

func classifyTransportError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return newError(ErrorUpstreamTimeout, "教务系统响应超时，请稍后重试", err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return newError(ErrorUpstreamTimeout, "教务系统响应超时，请稍后重试", err)
	}
	return newError(ErrorUpstreamError, "连接教务系统失败，请稍后重试", err)
}
