package main

import (
	"net/http"
	"testing"
	"time"

	"simplecontainerregistry/internal/config"
)

func TestNewHTTPServerAppliesConfiguredLimits(t *testing.T) {
	cfg := config.Default()
	cfg.HTTP.ReadTimeout = config.Duration(11 * time.Minute)
	cfg.HTTP.WriteTimeout = config.Duration(12 * time.Minute)
	cfg.HTTP.IdleTimeout = config.Duration(3 * time.Minute)
	cfg.HTTP.MaxHeaderBytes = 2 << 20
	server := newHTTPServer(cfg, http.NotFoundHandler())
	if server.ReadHeaderTimeout != 10*time.Second || server.ReadTimeout != 11*time.Minute || server.WriteTimeout != 12*time.Minute || server.IdleTimeout != 3*time.Minute || server.MaxHeaderBytes != 2<<20 {
		t.Fatalf("unexpected HTTP server limits: %#v", server)
	}
}

func TestUploadCleanupIntervalIsBoundedByUploadTTL(t *testing.T) {
	if got := uploadCleanupInterval(10 * time.Minute); got != 5*time.Minute {
		t.Fatalf("uploadCleanupInterval() = %s, want 5m", got)
	}
	if got := uploadCleanupInterval(time.Nanosecond); got != time.Nanosecond {
		t.Fatalf("uploadCleanupInterval(nanosecond) = %s, want 1ns", got)
	}
}
