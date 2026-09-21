package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaultsWhenConfigMissingFailsClosed(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil {
		t.Fatal("Load() error = nil")
	}
	if cfg.HTTP.Port != 5000 {
		t.Fatalf("expected default port 5000, got %d", cfg.HTTP.Port)
	}
	if !cfg.HTTP.SecureCookies {
		t.Fatal("expected secure cookies to be enabled by default")
	}
	if cfg.HTTP.ReadTimeout.Std() != 30*time.Minute || cfg.HTTP.WriteTimeout.Std() != 30*time.Minute || cfg.HTTP.IdleTimeout.Std() != 2*time.Minute || cfg.HTTP.MaxHeaderBytes != 1<<20 {
		t.Fatalf("unexpected default HTTP limits: %#v", cfg.HTTP)
	}
	if cfg.Storage.RootDirectory != "/var/lib/scr/registry" {
		t.Fatalf("unexpected default storage root %q", cfg.Storage.RootDirectory)
	}
	if cfg.Storage.MaxUploadBytes != 10<<30 || cfg.Storage.MaxUploadSessions != 100 || cfg.Storage.UploadTTL.Std() != 24*time.Hour {
		t.Fatalf("unexpected default upload limits: %#v", cfg.Storage)
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
	if err == nil {
		t.Fatal("Load() error = nil")
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
  allowInsecureHTTP: true
  publicURL: "https://registry.example.test"
  trustForwardedHeaders: true
  trustedProxyCIDRs: ["10.0.0.0/8"]
  readTimeout: "20m"
  writeTimeout: "25m"
  idleTimeout: "3m"
  maxHeaderBytes: 2097152
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
	if cfg.HTTP.PublicURL != "https://registry.example.test" || !cfg.HTTP.TrustForwardedHeaders {
		t.Fatalf("unexpected http proxy config: %#v", cfg.HTTP)
	}
	if cfg.HTTP.ReadTimeout.Std() != 20*time.Minute || cfg.HTTP.WriteTimeout.Std() != 25*time.Minute || cfg.HTTP.IdleTimeout.Std() != 3*time.Minute || cfg.HTTP.MaxHeaderBytes != 2<<20 {
		t.Fatalf("unexpected http limits: %#v", cfg.HTTP)
	}
	if cfg.Storage.GCDelay.Std() != 30*time.Minute {
		t.Fatalf("unexpected gc delay %s", cfg.Storage.GCDelay.Std())
	}
}

func TestValidateRejectsInvalidPublicURL(t *testing.T) {
	cfg := Default()
	cfg.HTTP.AllowInsecureHTTP = true
	cfg.HTTP.PublicURL = "https://registry.example.test/path"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected public url with path to be rejected")
	}
}

func TestValidateHTTPSecurityRequirements(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"non-positive read timeout", func(cfg *Config) { cfg.HTTP.ReadTimeout = 0 }},
		{"small header limit", func(cfg *Config) { cfg.HTTP.MaxHeaderBytes = 512 }},
		{"insecure cookies without opt-in", func(cfg *Config) { cfg.HTTP.SecureCookies = false }},
		{"http public URL without opt-in", func(cfg *Config) { cfg.HTTP.PublicURL = "http://registry.example.test" }},
		{"missing public URL without opt-in", func(cfg *Config) {}},
		{"forwarded headers without CIDRs", func(cfg *Config) {
			cfg.HTTP.TrustForwardedHeaders = true
			cfg.HTTP.PublicURL = "https://registry.example.test"
		}},
		{"forwarded headers without HTTPS public URL", func(cfg *Config) {
			cfg.HTTP.TrustForwardedHeaders = true
			cfg.HTTP.TrustedProxyCIDRs = []string{"10.0.0.0/8"}
			cfg.HTTP.PublicURL = "http://registry.example.test"
			cfg.HTTP.AllowInsecureHTTP = true
		}},
		{"invalid proxy CIDR", func(cfg *Config) {
			cfg.HTTP.PublicURL = "https://registry.example.test"
			cfg.HTTP.TrustedProxyCIDRs = []string{"not-a-cidr"}
		}},
		{"world-trusting proxy CIDR", func(cfg *Config) {
			cfg.HTTP.PublicURL = "https://registry.example.test"
			cfg.HTTP.TrustedProxyCIDRs = []string{"0.0.0.0/0"}
		}},
		{"world-trusting IPv6 proxy CIDR", func(cfg *Config) {
			cfg.HTTP.PublicURL = "https://registry.example.test"
			cfg.HTTP.TrustedProxyCIDRs = []string{"::/0"}
		}},
		{"proxy CIDR with host bits set", func(cfg *Config) {
			cfg.HTTP.PublicURL = "https://registry.example.test"
			cfg.HTTP.TrustedProxyCIDRs = []string{"10.1.2.3/8"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := Default()
			test.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestValidateAcceptsHTTPSPublicURLOrInsecureOptIn(t *testing.T) {
	https := Default()
	https.HTTP.PublicURL = "https://registry.example.test"
	if err := https.Validate(); err != nil {
		t.Fatalf("HTTPS public URL Validate() error = %v", err)
	}

	insecure := Default()
	insecure.HTTP.AllowInsecureHTTP = true
	if err := insecure.Validate(); err != nil {
		t.Fatalf("insecure opt-in Validate() error = %v", err)
	}
}

func TestValidateAllowsPlainHTTPOnLoopbackWithoutOptIn(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "127.0.1.1", "::1", "localhost"} {
		t.Run(address, func(t *testing.T) {
			cfg := Default()
			cfg.HTTP.Address = address
			cfg.HTTP.SecureCookies = false
			cfg.HTTP.AllowInsecureHTTP = false
			cfg.HTTP.PublicURL = ""
			if err := cfg.Validate(); err != nil {
				t.Fatalf("loopback Validate() error = %v", err)
			}
		})
	}
}

func TestValidateStillRequiresOptInForNonLoopbackBinds(t *testing.T) {
	for _, address := range []string{"0.0.0.0", "", "::", "192.168.1.10"} {
		t.Run(address, func(t *testing.T) {
			cfg := Default()
			cfg.HTTP.Address = address
			cfg.HTTP.SecureCookies = false
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestValidateAcceptsNarrowProxyCIDRs(t *testing.T) {
	cfg := Default()
	cfg.HTTP.PublicURL = "https://registry.example.test"
	cfg.HTTP.TrustForwardedHeaders = true
	cfg.HTTP.TrustedProxyCIDRs = []string{"10.0.0.0/8", "192.168.1.0/24", "fd00::/64", "127.0.0.1/32"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsNonPositiveUploadLimits(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(cfg *Config) { cfg.Storage.MaxUploadBytes = 0 },
		func(cfg *Config) { cfg.Storage.MaxUploadSessions = 0 },
		func(cfg *Config) { cfg.Storage.UploadTTL = 0 },
	} {
		cfg := Default()
		if cfg.HTTP.Address == "0.0.0.0" {
			cfg.HTTP.AllowInsecureHTTP = true
		}
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Fatal("Validate() error = nil")
		}
	}
}
