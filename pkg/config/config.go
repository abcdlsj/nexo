package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/abcdlsj/nexo/pkg/proxy"
	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	Email      string                   `mapstructure:"email"`
	Cloudflare CloudflareConfig         `mapstructure:"cloudflare"`
	Wildcards  []string                 `mapstructure:"wildcards"` // Wildcard domains (e.g. *.example.com)
	Proxies    map[string]*proxy.Config `mapstructure:"proxies"`
	BaseDir    string                   `mapstructure:"base_dir"`
	CertDir    string                   `mapstructure:"cert_dir"`
	ListenAddr string                   `mapstructure:"listen_addr"`
	AdminAddr  string                   `mapstructure:"admin_addr"`
	LogLevel   string                   `mapstructure:"log_level"`
}

// CloudflareConfig represents Cloudflare-specific configuration
type CloudflareConfig struct {
	APIToken string `mapstructure:"api_token"`
}

// Load loads the configuration from file
func Load(cfgFile string) (*Config, error) {
	v := viper.NewWithOptions(viper.KeyDelimiter(":"))

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		// Default config locations
		v.AddConfigPath("/etc/nexo")
		v.AddConfigPath("$HOME/.nexo")
		v.AddConfigPath(".")
		v.SetConfigType("yaml")
		v.SetConfigName("config")
	}

	// Environment variables support, e.g. NEXO_CLOUDFLARE_API_TOKEN
	v.SetEnvPrefix("NEXO")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", ":", "_"))
	v.AutomaticEnv()

	// Set default values
	v.SetDefault("email", "admin@example.com")
	v.SetDefault("cloudflare:api_token", "")
	v.SetDefault("wildcards", []string{})
	v.SetDefault("proxies", map[string]any{})
	v.SetDefault("listen_addr", ":443")
	v.SetDefault("admin_addr", ":8080")
	v.SetDefault("log_level", "info")

	// Determine config directory
	configDir := "/etc/nexo"
	if os.Getuid() != 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("error getting home directory: %v", err)
		}
		configDir = filepath.Join(home, ".nexo")
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, create it with default values
			if err := os.MkdirAll(configDir, 0755); err != nil {
				return nil, fmt.Errorf("error creating config directory: %v", err)
			}

			configFile := filepath.Join(configDir, "config.yaml")
			v.SetConfigFile(configFile)

			// Set base directory and cert directory
			v.Set("base_dir", configDir)
			v.Set("cert_dir", filepath.Join(configDir, "certs"))
			v.Set("listen_addr", v.GetString("listen_addr"))
			v.Set("admin_addr", v.GetString("admin_addr"))
			v.Set("log_level", v.GetString("log_level"))

			if err := v.SafeWriteConfig(); err != nil {
				return nil, fmt.Errorf("error creating config file: %v", err)
			}
		} else {
			return nil, fmt.Errorf("error reading config file: %v", err)
		}
	}

	// Ensure base_dir and cert_dir are set
	if v.GetString("base_dir") == "" {
		v.Set("base_dir", configDir)
		v.Set("cert_dir", filepath.Join(configDir, "certs"))
		if err := v.WriteConfig(); err != nil {
			return nil, fmt.Errorf("error saving config with base directory: %v", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %v", err)
	}

	// Validate required configuration
	if cfg.Cloudflare.APIToken == "" {
		return nil, fmt.Errorf("cloudflare API token not configured")
	}

	return &cfg, nil
}

// Save saves the configuration to file
func Save(v *viper.Viper) error {
	return v.WriteConfig()
}
