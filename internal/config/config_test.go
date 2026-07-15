package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaultsWhenConfigMissing(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTP.Port != 5000 {
		t.Fatalf("expected default port 5000, got %d", cfg.HTTP.Port)
	}
	if !cfg.HTTP.SecureCookies {
		t.Fatal("expected secure cookies to be enabled by default")
	}
	if cfg.Storage.RootDirectory != "/var/lib/scr/registry" {
		t.Fatalf("unexpected default storage root %q", cfg.Storage.RootDirectory)
	}
	if cfg.Database.DSN != "/var/lib/scr/scr.db" {
		t.Fatalf("unexpected default database dsn %q", cfg.Database.DSN)
	}
	if cfg.Auth.TokenTTL.Std() != 10*time.Minute {
		t.Fatalf("unexpected token ttl %s", cfg.Auth.TokenTTL.Std())
	}
}

func TestLoadAppliesBootstrapEnvironmentWhenConfigMissing(t *testing.T) {
	t.Setenv("SCR_BOOTSTRAP_ADMIN_USERNAME", "admin")
	t.Setenv("SCR_BOOTSTRAP_ADMIN_PASSWORD", "secret")

	cfg, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Bootstrap.AdminUsername != "admin" || cfg.Bootstrap.AdminPassword != "secret" {
		t.Fatalf("expected bootstrap env values, got %#v", cfg.Bootstrap)
	}
}

func TestLoadParsesDurationFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := []byte(`
http:
  address: "127.0.0.1"
  port: 5000
  secureCookies: false
storage:
  rootDirectory: "/tmp/registry"
  gcDelay: "30m"
  gcInterval: "12h"
database:
  driver: "sqlite"
  dsn: "/tmp/scr.db"
auth:
  issuer: "issuer"
  service: "service"
  tokenTTL: "5m"
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Auth.TokenTTL.Std() != 5*time.Minute {
		t.Fatalf("unexpected token ttl %s", cfg.Auth.TokenTTL.Std())
	}
	if cfg.HTTP.SecureCookies {
		t.Fatal("expected secure cookies to be configurable")
	}
	if cfg.Storage.GCDelay.Std() != 30*time.Minute {
		t.Fatalf("unexpected gc delay %s", cfg.Storage.GCDelay.Std())
	}
}
