package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config 保存后端运行所需配置，全部来源于环境变量并提供明确默认值。
type Config struct {
	Env               string
	HTTPAddr          string
	HTTPMaxBodyBytes  int64
	TrustedProxyCIDRs []string
	CORSAllowOrigins  []string

	JWXTAccessMode string
	JWXTTimeout    time.Duration

	AuthTxTTL        time.Duration
	AuthTxMaxEntries int
}

// Load 从环境变量加载配置并校验合法性。
func Load() (Config, error) {
	cfg := Config{
		Env:               strings.ToLower(getEnvDefault("APP_ENV", "dev")),
		HTTPAddr:          getEnvDefault("HTTP_ADDR", ":8080"),
		HTTPMaxBodyBytes:  getEnvInt64Default("HTTP_MAX_BODY_BYTES", 1<<20),
		TrustedProxyCIDRs: splitCSV(os.Getenv("TRUSTED_PROXIES")),
		CORSAllowOrigins:  splitCSV(os.Getenv("CORS_ALLOW_ORIGINS")),
		JWXTAccessMode:    strings.ToLower(getEnvDefault("JWXT_ACCESS_MODE", "auto")),
		JWXTTimeout:       time.Duration(getEnvIntDefault("JWXT_TIMEOUT_SECONDS", 20)) * time.Second,
		AuthTxTTL:         time.Duration(getEnvIntDefault("AUTH_TX_TTL_SECONDS", 300)) * time.Second,
		AuthTxMaxEntries:  getEnvIntDefault("AUTH_TX_MAX_ENTRIES", 500),
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate 校验启动配置。
func (c Config) Validate() error {
	if c.Env != "dev" && c.Env != "prod" && c.Env != "test" {
		return fmt.Errorf("无效的 APP_ENV: %q（仅支持 dev/prod/test）", c.Env)
	}
	if strings.TrimSpace(c.HTTPAddr) == "" {
		return fmt.Errorf("HTTP_ADDR 不能为空")
	}
	if c.HTTPMaxBodyBytes <= 0 {
		return fmt.Errorf("HTTP_MAX_BODY_BYTES 必须大于 0")
	}
	switch c.JWXTAccessMode {
	case "auto", "direct", "campus", "wfw", "external":
	default:
		return fmt.Errorf("无效的 JWXT_ACCESS_MODE: %q（仅支持 auto/direct/campus/wfw/external）", c.JWXTAccessMode)
	}
	if c.JWXTTimeout <= 0 {
		return fmt.Errorf("JWXT_TIMEOUT_SECONDS 必须大于 0")
	}
	if c.AuthTxTTL <= 0 {
		return fmt.Errorf("AUTH_TX_TTL_SECONDS 必须大于 0")
	}
	if c.AuthTxMaxEntries <= 0 {
		return fmt.Errorf("AUTH_TX_MAX_ENTRIES 必须大于 0")
	}
	return nil
}

func getEnvDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func getEnvIntDefault(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	val, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return val
}

func getEnvInt64Default(key string, fallback int64) int64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	val, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fallback
	}
	return val
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
