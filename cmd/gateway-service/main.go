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
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

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

	verifier, err := gateway.NewSupabaseVerifier(
		cfg.SupabaseURL,
		cfg.SupabaseAnonKey,
		gateway.TimeoutClient(cfg.RequestTimeout),
	)
	if err != nil {
		return err
	}

	api := gateway.New(gateway.Options{
		Verifier:       verifier,
		InternalToken:  cfg.InternalToken,
		AuthCookieName: cfg.AuthCookieName,
		Routes:         cfg.Routes,
		Client:         gateway.TimeoutClient(cfg.RequestTimeout),
		MaxBodyBytes:   cfg.MaxBodyBytes,
	})

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           api.Handler(),
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
