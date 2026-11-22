package server

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/farshore07/gdou_helper_backend/internal/integration/jwxt"
	"github.com/gin-gonic/gin"
)

func (h *handler) health(c *gin.Context) {
	if c.FullPath() == "/health" {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
		return
	}
	ok(c, gin.H{
		"env":         h.cfg.Env,
		"started_at":  h.startedAt.Format(time.RFC3339),
		"database":    "disabled",
		"access_mode": string(h.jwxt.DefaultAccessMode()),
	})
}

type jwxtLoginRequest struct {
	Username          string `json:"username" binding:"required"`
	Password          string `json:"password" binding:"required"`
	DeviceFingerprint string `json:"device_fingerprint"`
	CaptchaToken      string `json:"captcha_token"`
	CaptchaCode       string `json:"captcha_code"`
	NetworkMode       string `json:"network_mode"`
}

func (h *handler) loginJWXT(c *gin.Context) {
	var req jwxtLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, badRequest("username 和 password 不能为空"))
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		fail(c, badRequest("username 和 password 不能为空"))
		return
	}

	var (
		outcome jwxt.LoginOutcome
		err     error
	)

	if strings.TrimSpace(req.CaptchaToken) != "" {
		captchaTx, takeErr := h.store.TakeCaptcha(strings.TrimSpace(req.CaptchaToken))
		if takeErr != nil {
			fail(c, mapJWXTError(takeErr))
			return
		}
		outcome, err = h.jwxt.CompleteCaptchaLogin(c.Request.Context(), captchaTx, req.Username, req.Password, req.CaptchaCode)
	} else {
		mode, parseErr := jwxt.ParseNetworkMode(req.NetworkMode, h.jwxt.DefaultAccessMode())
		if parseErr != nil {
			fail(c, badRequest(parseErr.Error()))
			return
		}
		outcome, err = h.jwxt.BeginLogin(c.Request.Context(), jwxt.BeginLoginInput{
			Username:          req.Username,
			Password:          req.Password,
			DeviceFingerprint: req.DeviceFingerprint,
			NetworkMode:       mode,
			CaptchaCode:       req.CaptchaCode,
		})
	}

	if err != nil {
		fail(c, mapJWXTError(err))
		return
	}

	h.writeLoginOutcome(c, outcome)
}

func (h *handler) writeLoginOutcome(c *gin.Context, outcome jwxt.LoginOutcome) {
	switch outcome.Status {
	case "success":
		ok(c, gin.H{
			"status":             "success",
			"message":            outcome.Message,
			"cookie":             outcome.Cookie,
			"device_fingerprint": outcome.DeviceFingerprint,
			"network_mode":       string(outcome.NetworkMode),
			"url":                outcome.URL,
			"is_admin":           false,
		})
	case "need_mfa":
		token, err := h.store.PutMFA(outcome.MfaTx)
		if err != nil {
			fail(c, mapJWXTError(err))
			return
		}
		methods := make([]string, 0, len(outcome.MfaTx.AvailableMethods))
		for _, m := range outcome.MfaTx.AvailableMethods {
			methods = append(methods, string(m))
		}
		ok(c, gin.H{
			"status":             "need_mfa",
			"message":            outcome.Message,
			"login_token":        token,
			"default_method":     string(outcome.MfaTx.DefaultMethod),
			"available_methods":  methods,
			"device_fingerprint": outcome.DeviceFingerprint,
			"network_mode":       string(outcome.NetworkMode),
			"url":                outcome.URL,
		})
	case "need_captcha":
		token, err := h.store.PutCaptcha(outcome.CaptchaTx)
		if err != nil {
			fail(c, mapJWXTError(err))
			return
		}
		ok(c, gin.H{
			"status":               "need_captcha",
			"message":              outcome.Message,
			"captcha_token":        token,
			"captcha_image":        base64.StdEncoding.EncodeToString(outcome.CaptchaTx.ImageBytes),
			"captcha_content_type": outcome.CaptchaTx.ContentType,
			"device_fingerprint":   outcome.DeviceFingerprint,
			"network_mode":         string(outcome.NetworkMode),
			"url":                  outcome.URL,
		})
	default:
		fail(c, APIError{
			Status:  http.StatusBadGateway,
			Code:    "JWXT_LOGIN_ERROR",
			Message: outcome.Message,
		})
	}
}

type mfaSendRequest struct {
	LoginToken string `json:"login_token" binding:"required"`
	Method     string `json:"method"`
}

func (h *handler) sendJWXTMFA(c *gin.Context) {
	var req mfaSendRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, badRequest("login_token 不能为空"))
		return
	}
	method, err := jwxt.ParseMfaMethod(req.Method)
	if err != nil {
		fail(c, badRequest(err.Error()))
		return
	}

	tx, release, err := h.store.AcquireMFA(strings.TrimSpace(req.LoginToken))
	if err != nil {
		fail(c, mapJWXTError(err))
		return
	}
	defer release(false)

	result, err := h.jwxt.SendMFACode(c.Request.Context(), tx, method)
	if err != nil {
		fail(c, mapJWXTError(err))
		return
	}
	ok(c, result)
}

type mfaVerifyRequest struct {
	LoginToken  string `json:"login_token" binding:"required"`
	Code        string `json:"code" binding:"required"`
	TrustDevice *bool  `json:"trust_device"`
}

func (h *handler) verifyJWXTMFA(c *gin.Context) {
	var req mfaVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, badRequest("login_token 和 code 不能为空"))
		return
	}

	trustDevice := true
	if req.TrustDevice != nil {
		trustDevice = *req.TrustDevice
	}

	tx, release, err := h.store.AcquireMFA(strings.TrimSpace(req.LoginToken))
	if err != nil {
		fail(c, mapJWXTError(err))
		return
	}

	consume := false
	defer func() {
		release(consume)
	}()

	outcome, err := h.jwxt.VerifyMFACode(c.Request.Context(), tx, req.Code, trustDevice)
	if err != nil {
		if jwErr, okErr := err.(*jwxt.Error); okErr && jwErr.Kind == jwxt.ErrorSessionExpired {
			consume = true
		}
		fail(c, mapJWXTError(err))
		return
	}

	consume = true
	h.writeLoginOutcome(c, outcome)
}

type cookieRequest struct {
	Cookie string `json:"cookie" binding:"required"`
}

func (h *handler) validateJWXTSession(c *gin.Context) {
	var req cookieRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, badRequest("cookie 不能为空"))
		return
	}
	result, err := h.jwxt.ValidateSession(c.Request.Context(), req.Cookie)
	if err != nil {
		fail(c, mapJWXTError(err))
		return
	}
	ok(c, result)
}

type jwxtQueryRequest struct {
	Cookie       string            `json:"cookie" binding:"required"`
	AcademicYear string            `json:"academic_year" binding:"required"`
	Term         string            `json:"term" binding:"required"`
	Extra        map[string]string `json:"extra"`
}

func (h *handler) queryJWXTTimetable(c *gin.Context) {
	var req jwxtQueryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, badRequest("cookie、academic_year、term 不能为空"))
		return
	}
	result, err := h.jwxt.QueryTimetable(c.Request.Context(), req.Cookie, req.AcademicYear, req.Term, req.Extra)
	if err != nil {
		fail(c, mapJWXTError(err))
		return
	}
	ok(c, result)
}

func (h *handler) queryJWXTGrades(c *gin.Context) {
	var req jwxtQueryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, badRequest("cookie、academic_year、term 不能为空"))
		return
	}
	result, err := h.jwxt.QueryGrades(c.Request.Context(), req.Cookie, req.AcademicYear, req.Term, req.Extra)
	if err != nil {
		fail(c, mapJWXTError(err))
		return
	}
	ok(c, result)
}

type gradeDetailRequest struct {
	Cookie string            `json:"cookie" binding:"required"`
	Query  map[string]string `json:"query"`
}

func (h *handler) queryJWXTGradeDetail(c *gin.Context) {
	var req gradeDetailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, badRequest("cookie 不能为空"))
		return
	}
	query := url.Values{}
	for key, value := range req.Query {
		query.Set(key, value)
	}
	result, err := h.jwxt.QueryGradeDetail(c.Request.Context(), req.Cookie, query)
	if err != nil {
		fail(c, mapJWXTError(err))
		return
	}
	ok(c, result)
}

func (h *handler) queryJWXTExams(c *gin.Context) {
	var req jwxtQueryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, badRequest("cookie、academic_year、term 不能为空"))
		return
	}
	result, err := h.jwxt.QueryExams(c.Request.Context(), req.Cookie, req.AcademicYear, req.Term, req.Extra)
	if err != nil {
		fail(c, mapJWXTError(err))
		return
	}
	ok(c, result)
}
