package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
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
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
}

type StorageConfig struct {
	RootDirectory string   `yaml:"rootDirectory"`
	Commit        bool     `yaml:"commit"`
	GC            bool     `yaml:"gc"`
	GCDelay       Duration `yaml:"gcDelay"`
	GCInterval    Duration `yaml:"gcInterval"`
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
			Address: "0.0.0.0",
			Port:    5000,
		},
		Storage: StorageConfig{
			RootDirectory: "/var/lib/scr/registry",
			Commit:        true,
			GC:            true,
			GCDelay:       Duration(time.Hour),
			GCInterval:    Duration(24 * time.Hour),
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
	if c.Storage.RootDirectory == "" {
		return fmt.Errorf("storage.rootDirectory is required")
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
