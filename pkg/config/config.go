package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/abcdlsj/nexo/pkg/proxy"
	"github.com/charmbracelet/log"
	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	Email      string                   `mapstructure:"email" yaml:"email"`
	Cloudflare CloudflareConfig         `mapstructure:"cloudflare" yaml:"cloudflare"`
	Wildcards  []string                 `mapstructure:"wildcards" yaml:"wildcards"` // Wildcard domains (e.g. *.example.com)
	Proxies    map[string]*proxy.Config `mapstructure:"proxies" yaml:"proxies"`
	BaseDir    string                   `mapstructure:"base_dir" yaml:"base_dir"`
	CertDir    string                   `mapstructure:"cert_dir" yaml:"cert_dir"`
	WebUI      WebUIConfig              `mapstructure:"webui" yaml:"webui,omitempty"`
	Auth       AuthConfig               `mapstructure:"auth" yaml:"auth,omitempty"`
	Staging    bool                     `mapstructure:"staging" yaml:"staging,omitempty"` // Use Let's Encrypt staging environment
}

// AuthConfig represents OAuth authentication configuration
type AuthConfig struct {
	GitHub     GitHubAuthConfig `mapstructure:"github" yaml:"github,omitempty"`
	AuthHost   string           `mapstructure:"auth_host" yaml:"auth_host,omitempty"`   // Unified auth domain for OAuth callback
	SecretKey  string           `mapstructure:"secret_key" yaml:"secret_key,omitempty"` // Secret key for signing tokens
	SessionTTL string           `mapstructure:"session_ttl" yaml:"session_ttl,omitempty"` // Session TTL (e.g. "24h")
}

// GitHubAuthConfig represents GitHub OAuth configuration
type GitHubAuthConfig struct {
	ClientID     string   `mapstructure:"client_id" yaml:"client_id,omitempty"`
	ClientSecret string   `mapstructure:"client_secret" yaml:"client_secret,omitempty"`
	AllowedUsers []string `mapstructure:"allowed_users" yaml:"allowed_users,omitempty"`
}

// WebUIConfig represents WebUI-specific configuration
type WebUIConfig struct {
	Port     string `mapstructure:"port" yaml:"port,omitempty"`         // WebUI port (default: 8080)
	Username string `mapstructure:"username" yaml:"username,omitempty"` // WebUI login username
	Password string `mapstructure:"password" yaml:"password,omitempty"` // WebUI login password (bcrypt hashed)
}

// CloudflareConfig represents Cloudflare-specific configuration
type CloudflareConfig struct {
	APIToken string `mapstructure:"api_token" yaml:"api_token"`
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

	// Set default values
	v.SetDefault("email", "admin@example.com")
	v.SetDefault("cloudflare:api_token", "")
	v.SetDefault("wildcards", []string{})
	v.SetDefault("proxies", map[string]any{})

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
		v.Set("cert_dir", filepath.Join(configDir, "cert"))
		if err := v.WriteConfig(); err != nil {
			return nil, fmt.Errorf("error saving config with base directory: %v", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %v", err)
	}

	// Note: Cloudflare API token is required for production use
	// but we allow it to be empty for local development/testing
	if cfg.Cloudflare.APIToken == "" {
		log.Warn("Cloudflare API token not configured - running in dev mode (no automatic certificates)")
	}

	return &cfg, nil
}

// Save saves the configuration to file
func Save(v *viper.Viper) error {
	return v.WriteConfig()
}

// GetWildcardDomain checks if a domain matches any configured wildcard domain
// Returns the wildcard domain (e.g., *.example.com) and true if matched
func (c *Config) GetWildcardDomain(domain string) (string, bool) {
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) != 2 {
		return "", false
	}

	wd := "*." + parts[1]
	for _, d := range c.Wildcards {
		if d == wd {
			return d, true
		}
	}

	return "", false
}
