package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/farshore07/gdou_helper_backend/internal/config"
	"github.com/farshore07/gdou_helper_backend/internal/integration/jwxt"
	"github.com/gin-gonic/gin"
)

// Server 封装 HTTP 路由与后台资源生命周期。
type Server struct {
	Handler http.Handler
	store   *AuthTxStore
}

// Close 释放后端持有的后台协程资源。
func (s *Server) Close() {
	if s != nil && s.store != nil {
		s.store.Close()
	}
}

type handler struct {
	cfg       config.Config
	jwxt      *jwxt.Client
	store     *AuthTxStore
	startedAt time.Time
}

// New 创建并装配 Gin 服务（支持注入自定义 jwxt.Client 便于单元测试）。
func New(cfg config.Config, jwxtClient *jwxt.Client) (*Server, error) {
	if cfg.Env == "prod" {
		gin.SetMode(gin.ReleaseMode)
	} else if cfg.Env == "test" {
		gin.SetMode(gin.TestMode)
	}

	if jwxtClient == nil {
		mode, err := jwxt.ParseNetworkMode(cfg.JWXTAccessMode, jwxt.NetworkModeAuto)
		if err != nil {
			return nil, err
		}
		jwxtClient = jwxt.NewClient(jwxt.ClientOptions{
			AccessMode: mode,
			Timeout:    cfg.JWXTTimeout,
		})
	}

	store := NewAuthTxStore(cfg.AuthTxTTL, cfg.AuthTxMaxEntries)
	h := &handler{
		cfg:       cfg,
		jwxt:      jwxtClient,
		store:     store,
		startedAt: time.Now(),
	}

	r := gin.New()
	r.HandleMethodNotAllowed = true
	r.Use(gin.Logger(), gin.Recovery())
	if err := r.SetTrustedProxies(cfg.TrustedProxyCIDRs); err != nil {
		store.Close()
		return nil, fmt.Errorf("可信代理配置无效: %w", err)
	}
	if cfg.HTTPMaxBodyBytes > 0 {
		r.Use(maxRequestBody(cfg.HTTPMaxBodyBytes))
	}
	if len(cfg.CORSAllowOrigins) > 0 {
		r.Use(corsMiddleware(cfg.CORSAllowOrigins))
	}

	// 统一 JSON 格式的 404 / 405，防止客户端（如未上线的电费路由）解析纯文本报错
	r.NoRoute(func(c *gin.Context) {
		fail(c, APIError{
			Status:  http.StatusNotFound,
			Code:    "NOT_FOUND",
			Message: "接口不存在",
		})
	})
	r.NoMethod(func(c *gin.Context) {
		fail(c, APIError{
			Status:  http.StatusMethodNotAllowed,
			Code:    "METHOD_NOT_ALLOWED",
			Message: "请求方法不支持",
		})
	})

	r.GET("/health", h.health)
	api := r.Group("/api/v1")
	api.GET("/health", h.health)

	jw := api.Group("/jwxt")
	jw.POST("/login", h.loginJWXT)
	jw.POST("/mfa/send", h.sendJWXTMFA)
	jw.POST("/mfa/verify", h.verifyJWXTMFA)
	jw.POST("/session/validate", h.validateJWXTSession)
	jw.POST("/timetable", h.queryJWXTTimetable)
	jw.POST("/grades", h.queryJWXTGrades)
	jw.POST("/grade-detail", h.queryJWXTGradeDetail)
	jw.POST("/exams", h.queryJWXTExams)

	return &Server{
		Handler: r,
		store:   store,
	}, nil
}

func maxRequestBody(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		c.Next()
	}
}

func corsMiddleware(allowed []string) gin.HandlerFunc {
	allowAll := false
	set := make(map[string]struct{}, len(allowed))
	for _, origin := range allowed {
		if origin == "*" {
			allowAll = true
			continue
		}
		set[strings.TrimRight(origin, "/")] = struct{}{}
	}
	return func(c *gin.Context) {
		origin := strings.TrimRight(c.GetHeader("Origin"), "/")
		if origin != "" {
			if allowAll {
				c.Header("Access-Control-Allow-Origin", "*")
			} else if _, ok := set[origin]; ok {
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Vary", "Origin")
			}
			c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
