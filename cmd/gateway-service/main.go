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

	"github.com/yinlerens/gateway-service/internal/gateway"
	"github.com/yinlerens/gateway-service/internal/telemetry"
)

func main() {
	slog.SetDefault(telemetry.NewJSONLogger(os.Stdout))

	if err := run(); err != nil {
		slog.Error("gateway service stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := gateway.LoadConfig()
	if err != nil {
		return err
	}

	shutdownTelemetry, err := telemetry.Setup(context.Background(), "gateway-service")
	if err != nil {
		return err
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTelemetry(shutdownCtx); err != nil {
			slog.Error("telemetry shutdown failed", "error", err)
		}
	}()

	authClient := gateway.TimeoutClient(cfg.RequestTimeout)
	authClient.Transport = telemetry.HTTPTransport(authClient.Transport)

	verifier, err := gateway.NewSupabaseVerifier(
		cfg.SupabaseURL,
		cfg.SupabaseAnonKey,
		authClient,
	)
	if err != nil {
		return err
	}

	var auditSink gateway.AuditSink
	if cfg.AuditDatabaseURL != "" {
		auditCtx, cancel := context.WithTimeout(context.Background(), cfg.AuditWriteTimeout)
		auditSink, err = gateway.NewPostgresAuditSink(auditCtx, cfg.AuditDatabaseURL, cfg.AuditWriteTimeout)
		cancel()
		if err != nil {
			return err
		}
		defer auditSink.Close()
	}

	upstreamClient := gateway.TimeoutClient(cfg.RequestTimeout)
	upstreamClient.Transport = telemetry.HTTPTransport(upstreamClient.Transport)

	api := gateway.New(gateway.Options{
		Verifier:          verifier,
		InternalToken:     cfg.InternalToken,
		AuthCookieName:    cfg.AuthCookieName,
		Routes:            cfg.Routes,
		Client:            upstreamClient,
		MaxBodyBytes:      cfg.MaxBodyBytes,
		AuditSink:         auditSink,
		AuditMaxBodyBytes: cfg.AuditMaxBodyBytes,
		AdminUserIDs:      cfg.AuditLogAdminUserIDs,
	})

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           telemetry.HTTPHandler(api.Handler()),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("gateway service listening", "addr", cfg.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}
