package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromEnvFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	content := "\uFEFF# 服务端监听配置\n" +
		"APP_ENV=prod\n" +
		"HTTP_ADDR=:9090 # 注释\n" +
		"JWXT_ACCESS_MODE=\"wfw\"\n" +
		"export JWXT_TIMEOUT_SECONDS=30\n"
	if err := os.WriteFile(envPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write .env failed: %v", err)
	}

	cfg, err := LoadFromFile(envPath, true)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}
	if cfg.Env != "prod" || cfg.HTTPAddr != ":9090" || cfg.JWXTAccessMode != "wfw" || cfg.JWXTTimeout.Seconds() != 30 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestEnvOverridesDotEnvAndNormalizesPort(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("HTTP_ADDR=8081\n"), 0o600); err != nil {
		t.Fatalf("write .env failed: %v", err)
	}

	cfg, err := LoadFromFile(envPath, true)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}
	if cfg.HTTPAddr != ":8081" {
		t.Fatalf("expected :8081, got %q", cfg.HTTPAddr)
	}

	t.Setenv("HTTP_ADDR", "127.0.0.1:18080")
	cfg2, err := LoadFromFile(envPath, true)
	if err != nil {
		t.Fatalf("LoadFromFile with env override failed: %v", err)
	}
	if cfg2.HTTPAddr != "127.0.0.1:18080" {
		t.Fatalf("expected env override 127.0.0.1:18080, got %q", cfg2.HTTPAddr)
	}
}

func TestMissingOptionalDotEnvFallsBackToDefaults(t *testing.T) {
	cfg, err := LoadFromFile(filepath.Join(t.TempDir(), "not-exist.env"), false)
	if err != nil {
		t.Fatalf("expected fallback to defaults, got err: %v", err)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Fatalf("expected default :8080, got %q", cfg.HTTPAddr)
	}
	if _, err := LoadFromFile(filepath.Join(t.TempDir(), "not-exist.env"), true); err == nil {
		t.Fatalf("expected error when explicit ENV_FILE is missing")
	}
}
