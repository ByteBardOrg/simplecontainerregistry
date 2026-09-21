package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	HTTP      HTTPConfig      `yaml:"http"`
	Storage   StorageConfig   `yaml:"storage"`
	Database  DatabaseConfig  `yaml:"database"`
	Auth      AuthConfig      `yaml:"auth"`
	Bootstrap BootstrapConfig `yaml:"bootstrap"`
}

type HTTPConfig struct {
	Address               string   `yaml:"address"`
	Port                  int      `yaml:"port"`
	SecureCookies         bool     `yaml:"secureCookies"`
	AllowInsecureHTTP     bool     `yaml:"allowInsecureHTTP"`
	PublicURL             string   `yaml:"publicURL"`
	TrustForwardedHeaders bool     `yaml:"trustForwardedHeaders"`
	TrustedProxyCIDRs     []string `yaml:"trustedProxyCIDRs"`
	ReadTimeout           Duration `yaml:"readTimeout"`
	WriteTimeout          Duration `yaml:"writeTimeout"`
	IdleTimeout           Duration `yaml:"idleTimeout"`
	MaxHeaderBytes        int      `yaml:"maxHeaderBytes"`
}

type StorageConfig struct {
	RootDirectory     string   `yaml:"rootDirectory"`
	GC                bool     `yaml:"gc"`
	GCDelay           Duration `yaml:"gcDelay"`
	GCInterval        Duration `yaml:"gcInterval"`
	MaxUploadBytes    int64    `yaml:"maxUploadBytes"`
	MaxUploadSessions int      `yaml:"maxUploadSessions"`
	UploadTTL         Duration `yaml:"uploadTTL"`
}

type DatabaseConfig struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

type AuthConfig struct {
	Issuer   string   `yaml:"issuer"`
	Service  string   `yaml:"service"`
	TokenTTL Duration `yaml:"tokenTTL"`
}

type BootstrapConfig struct {
	AdminUsername string `yaml:"adminUsername"`
	AdminPassword string `yaml:"adminPassword"`
}

type Duration time.Duration

func Load(path string) (Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return Config{}, err
		}
		cfg.applyEnvironment()
		return cfg, cfg.Validate()
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}

	cfg.applyEnvironment()

	return cfg, cfg.Validate()
}

func (c *Config) applyEnvironment() {
	if c.Bootstrap.AdminUsername == "" {
		c.Bootstrap.AdminUsername = os.Getenv("SCR_BOOTSTRAP_ADMIN_USERNAME")
	}
	if c.Bootstrap.AdminPassword == "" {
		c.Bootstrap.AdminPassword = os.Getenv("SCR_BOOTSTRAP_ADMIN_PASSWORD")
	}
}

func Default() Config {
	return Config{
		HTTP: HTTPConfig{
			Address:        "0.0.0.0",
			Port:           5000,
			SecureCookies:  true,
			ReadTimeout:    Duration(30 * time.Minute),
			WriteTimeout:   Duration(30 * time.Minute),
			IdleTimeout:    Duration(2 * time.Minute),
			MaxHeaderBytes: 1 << 20,
		},
		Storage: StorageConfig{
			RootDirectory:     "/var/lib/scr/registry",
			GC:                true,
			GCDelay:           Duration(time.Hour),
			GCInterval:        Duration(24 * time.Hour),
			MaxUploadBytes:    10 << 30,
			MaxUploadSessions: 100,
			UploadTTL:         Duration(24 * time.Hour),
		},
		Database: DatabaseConfig{
			Driver: "sqlite",
			DSN:    "/var/lib/scr/scr.db",
		},
		Auth: AuthConfig{
			Issuer:   "scr",
			Service:  "scr",
			TokenTTL: Duration(10 * time.Minute),
		},
	}
}

func (c Config) Validate() error {
	if c.HTTP.Port <= 0 || c.HTTP.Port > 65535 {
		return fmt.Errorf("http.port must be between 1 and 65535")
	}
	if c.HTTP.ReadTimeout <= 0 {
		return fmt.Errorf("http.readTimeout must be positive")
	}
	if c.HTTP.WriteTimeout <= 0 {
		return fmt.Errorf("http.writeTimeout must be positive")
	}
	if c.HTTP.IdleTimeout <= 0 {
		return fmt.Errorf("http.idleTimeout must be positive")
	}
	if c.HTTP.MaxHeaderBytes < 1024 || c.HTTP.MaxHeaderBytes > 16<<20 {
		return fmt.Errorf("http.maxHeaderBytes must be between 1024 and 16777216")
	}
	// A loopback bind cannot be reached off-host, so plain HTTP there is
	// already confined to the local machine and needs no explicit opt-in.
	insecureAllowed := c.HTTP.AllowInsecureHTTP || isLoopbackAddress(c.HTTP.Address)

	var publicURL *url.URL
	if c.HTTP.PublicURL != "" {
		parsed, err := url.ParseRequestURI(c.HTTP.PublicURL)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return fmt.Errorf("http.publicURL must be an absolute http or https URL")
		}
		if parsed.RawQuery != "" || parsed.Fragment != "" || strings.Trim(parsed.Path, "/") != "" {
			return fmt.Errorf("http.publicURL must not include path, query, or fragment")
		}
		publicURL = parsed
		if parsed.Scheme == "http" && !insecureAllowed {
			return fmt.Errorf("http.publicURL %q uses http; set http.allowInsecureHTTP: true to serve plain HTTP on a non-loopback address", c.HTTP.PublicURL)
		}
	}
	if (publicURL == nil || publicURL.Scheme != "https") && !insecureAllowed {
		return fmt.Errorf("http.publicURL must be set to the public https origin when binding the non-loopback address %q; set http.allowInsecureHTTP: true only to serve plain HTTP there", c.HTTP.Address)
	}
	if !c.HTTP.SecureCookies && !insecureAllowed {
		return fmt.Errorf("http.secureCookies: false requires http.allowInsecureHTTP: true when binding the non-loopback address %q", c.HTTP.Address)
	}
	for _, rawCIDR := range c.HTTP.TrustedProxyCIDRs {
		ip, network, err := net.ParseCIDR(rawCIDR)
		if err != nil {
			return fmt.Errorf("invalid http.trustedProxyCIDRs entry %q", rawCIDR)
		}
		if ones, _ := network.Mask.Size(); ones == 0 {
			return fmt.Errorf("http.trustedProxyCIDRs entry %q trusts every address; list only the reverse proxy networks", rawCIDR)
		}
		if !ip.Equal(network.IP) {
			return fmt.Errorf("http.trustedProxyCIDRs entry %q has host bits set, use %q", rawCIDR, network.String())
		}
	}
	if c.HTTP.TrustForwardedHeaders {
		if len(c.HTTP.TrustedProxyCIDRs) == 0 {
			return fmt.Errorf("http.trustedProxyCIDRs is required when http.trustForwardedHeaders is true")
		}
		if publicURL == nil || publicURL.Scheme != "https" {
			return fmt.Errorf("http.trustForwardedHeaders requires an https http.publicURL")
		}
	}
	if c.Storage.RootDirectory == "" {
		return fmt.Errorf("storage.rootDirectory is required")
	}
	if c.Storage.MaxUploadBytes <= 0 {
		return fmt.Errorf("storage.maxUploadBytes must be positive")
	}
	if c.Storage.MaxUploadSessions <= 0 {
		return fmt.Errorf("storage.maxUploadSessions must be positive")
	}
	if c.Storage.UploadTTL <= 0 {
		return fmt.Errorf("storage.uploadTTL must be positive")
	}
	if c.Database.Driver != "sqlite" {
		return fmt.Errorf("unsupported database.driver %q", c.Database.Driver)
	}
	if c.Database.DSN == "" {
		return fmt.Errorf("database.dsn is required")
	}
	if c.Auth.Issuer == "" {
		return fmt.Errorf("auth.issuer is required")
	}
	if c.Auth.Service == "" {
		return fmt.Errorf("auth.service is required")
	}
	if c.Auth.TokenTTL <= 0 {
		return fmt.Errorf("auth.tokenTTL must be positive")
	}
	if (c.Bootstrap.AdminUsername == "") != (c.Bootstrap.AdminPassword == "") {
		return fmt.Errorf("bootstrap admin username and password must be provided together")
	}
	return nil
}

func isLoopbackAddress(address string) bool {
	if address == "localhost" {
		return true
	}
	ip := net.ParseIP(address)
	return ip != nil && ip.IsLoopback()
}

func (h HTTPConfig) ListenAddress() string {
	return net.JoinHostPort(h.Address, strconv.Itoa(h.Port))
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var raw string
	if err := value.Decode(&raw); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Std() time.Duration {
	return time.Duration(d)
}
