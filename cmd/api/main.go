package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/farshore07/gdou_helper_backend/internal/config"
	"github.com/farshore07/gdou_helper_backend/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("加载配置失败", "error", err)
		os.Exit(1)
	}

	app, err := server.New(cfg, nil)
	if err != nil {
		slog.Error("初始化服务失败", "error", err)
		os.Exit(1)
	}
	defer app.Close()

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           app.Handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      cfg.JWXTTimeout + 15*time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("gdou_helper_backend 启动",
			"addr", cfg.HTTPAddr,
			"env", cfg.Env,
			"access_mode", cfg.JWXTAccessMode,
			"database", "disabled",
		)
		if listenErr := httpServer.ListenAndServe(); listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
			errCh <- listenErr
		}
		close(errCh)
	}()

	select {
	case listenErr := <-errCh:
		if listenErr != nil {
			slog.Error("HTTP 服务异常退出", "error", listenErr)
			os.Exit(1)
		}
	case <-ctx.Done():
		slog.Info("收到退出信号，正在优雅关闭服务")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if shutdownErr := httpServer.Shutdown(shutdownCtx); shutdownErr != nil {
			slog.Error("优雅关闭服务失败", "error", shutdownErr)
			os.Exit(1)
		}
	}
}
