package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config 保存后端运行所需配置，优先读取系统环境变量，其次读取 .env 文件，最后回退默认值。
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

// Load 加载配置并校验合法性（支持通过 ENV_FILE 指定 .env 文件路径，默认读取当前目录 .env）。
func Load() (Config, error) {
	envFile := strings.TrimSpace(os.Getenv("ENV_FILE"))
	explicitFile := envFile != ""
	if !explicitFile {
		envFile = ".env"
	}
	return LoadFromFile(envFile, explicitFile)
}

// LoadFromFile 从指定 .env 文件与系统环境变量合并加载配置（系统环境变量优先级更高）。
func LoadFromFile(path string, mustExist bool) (Config, error) {
	fileVars, err := parseEnvFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !mustExist {
			fileVars = nil
		} else {
			return Config{}, fmt.Errorf("读取配置文件 %s 失败: %w", path, err)
		}
	}

	lookup := func(key string) string {
		if val, ok := os.LookupEnv(key); ok {
			return strings.TrimSpace(val)
		}
		if fileVars != nil {
			return strings.TrimSpace(fileVars[key])
		}
		return ""
	}

	cfg := Config{
		Env:               strings.ToLower(getDefault(lookup, "APP_ENV", "dev")),
		HTTPAddr:          normalizeHTTPAddr(getDefault(lookup, "HTTP_ADDR", ":8080")),
		HTTPMaxBodyBytes:  getInt64Default(lookup, "HTTP_MAX_BODY_BYTES", 1<<20),
		TrustedProxyCIDRs: splitCSV(lookup("TRUSTED_PROXIES")),
		CORSAllowOrigins:  splitCSV(lookup("CORS_ALLOW_ORIGINS")),
		JWXTAccessMode:    strings.ToLower(getDefault(lookup, "JWXT_ACCESS_MODE", "auto")),
		JWXTTimeout:       time.Duration(getIntDefault(lookup, "JWXT_TIMEOUT_SECONDS", 20)) * time.Second,
		AuthTxTTL:         time.Duration(getIntDefault(lookup, "AUTH_TX_TTL_SECONDS", 300)) * time.Second,
		AuthTxMaxEntries:  getIntDefault(lookup, "AUTH_TX_MAX_ENTRIES", 500),
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

func parseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	values := make(map[string]string)
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if lineNo == 1 {
			line = strings.TrimPrefix(line, "\uFEFF")
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		key, rawVal, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		values[key] = parseEnvValue(rawVal)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func parseEnvValue(raw string) string {
	val := strings.TrimSpace(raw)
	if len(val) >= 2 {
		if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
			return val[1 : len(val)-1]
		}
	}
	if idx := strings.Index(val, " #"); idx >= 0 {
		val = strings.TrimSpace(val[:idx])
	}
	return val
}

func normalizeHTTPAddr(addr string) string {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return ""
	}
	if port, err := strconv.Atoi(trimmed); err == nil && port > 0 && port <= 65535 {
		return ":" + trimmed
	}
	return trimmed
}

func getDefault(lookup func(string) string, key, fallback string) string {
	if value := lookup(key); value != "" {
		return value
	}
	return fallback
}

func getIntDefault(lookup func(string) string, key string, fallback int) int {
	raw := lookup(key)
	if raw == "" {
		return fallback
	}
	val, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return val
}

func getInt64Default(lookup func(string) string, key string, fallback int64) int64 {
	raw := lookup(key)
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
