package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/xd-dash/atman/internal/gateway"
	"github.com/xd-dash/atman/internal/marai"
)

func required(name string) string {
	value := os.Getenv(name)
	if value == "" {
		slog.Error("required environment variable is missing", "name", name)
		os.Exit(2)
	}
	return value
}

func main() {
	cfg := gateway.Config{
		Audience:              required("ATMAN_AUDIENCE"),
		AllowedServiceAccount: required("ATMAN_ALLOWED_SERVICE_ACCOUNT"),
		MaxBodyBytes:          8 << 20,
	}
	if value := os.Getenv("ATMAN_MAX_BODY_BYTES"); value != "" {
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil || parsed < 1 || parsed > 64<<20 {
			slog.Error("invalid ATMAN_MAX_BODY_BYTES")
			os.Exit(2)
		}
		cfg.MaxBodyBytes = parsed
	}

	kms, err := marai.New(marai.Config{
		Socket:       required("MARAI_REDIS_SOCKET"),
		User:         required("MARAI_REDIS_USER"),
		PasswordFile: required("MARAI_REDIS_PASSWORD_FILE"),
		Timeout:      5 * time.Second,
	})
	if err != nil {
		slog.Error("configure marai client", "error", err)
		os.Exit(2)
	}

	handler, err := gateway.New(cfg, gateway.GoogleVerifier{}, kms)
	if err != nil {
		slog.Error("configure gateway", "error", err)
		os.Exit(2)
	}

	listen := os.Getenv("ATMAN_LISTEN")
	if listen == "" {
		listen = ":8443"
	}
	server := &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}

	errs := make(chan error, 1)
	go func() {
		certFile, keyFile := os.Getenv("ATMAN_TLS_CERT_FILE"), os.Getenv("ATMAN_TLS_KEY_FILE")
		if certFile == "" || keyFile == "" {
			if os.Getenv("ATMAN_ALLOW_INSECURE_HTTP") != "1" {
				errs <- errors.New("TLS files are required unless ATMAN_ALLOW_INSECURE_HTTP=1")
				return
			}
			errs <- server.ListenAndServe()
			return
		}
		errs <- server.ListenAndServeTLS(certFile, keyFile)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server stopped", "error", err)
			os.Exit(1)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown", "error", err)
		os.Exit(1)
	}
}
