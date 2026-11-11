package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/abcdlsj/nexo/pkg/proxy"
	"github.com/charmbracelet/log"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	Email      string                   `mapstructure:"email" yaml:"email"`
	Cloudflare CloudflareConfig         `mapstructure:"cloudflare" yaml:"cloudflare"`
	Wildcards  []string                 `mapstructure:"wildcards" yaml:"wildcards"` // Wildcard domains (e.g. *.example.com)
	Proxies    map[string]*proxy.Config `mapstructure:"proxies" yaml:"proxies"`
	Docker     DockerConfig             `mapstructure:"docker" yaml:"docker,omitempty"`
	BaseDir    string                   `mapstructure:"base_dir" yaml:"base_dir"`
	CertDir    string                   `mapstructure:"cert_dir" yaml:"cert_dir"`
	WebUI      WebUIConfig              `mapstructure:"webui" yaml:"webui,omitempty"`
	Auth       AuthConfig               `mapstructure:"auth" yaml:"auth,omitempty"`
	Security   SecurityConfig           `mapstructure:"security" yaml:"security,omitempty"`
	Staging    bool                     `mapstructure:"staging" yaml:"staging,omitempty"` // Use Let's Encrypt staging environment

	// ControlPlane exposes the machine-readable control API used by a fleet
	// coordinator. Disabled by default; enabling it never changes data-plane
	// routing.
	ControlPlane ControlPlaneConfig `mapstructure:"control_plane" yaml:"control_plane,omitempty"`

	// WriteTimeout optionally caps the total response write time for all routes.
	// Accepts Go duration strings (e.g. "2m"); empty or "0" disables the cap.
	// Routes can override this with their own write_timeout.
	WriteTimeout string `mapstructure:"write_timeout" yaml:"write_timeout,omitempty"`

	// ResponseHeaderTimeout caps how long the proxy waits for upstream response
	// headers for all routes. Accepts Go duration strings; "0" waits
	// indefinitely. Routes can override this with their own
	// response_header_timeout. When neither is set, the historical 30s default
	// applies.
	ResponseHeaderTimeout string `mapstructure:"response_header_timeout" yaml:"response_header_timeout,omitempty"`

	// MaxRequestBody caps the request body size accepted from clients for all
	// routes. Accepts byte sizes such as "10MB", "512KB" or a raw byte count;
	// empty keeps the 10MB default.
	MaxRequestBody string `mapstructure:"max_request_body" yaml:"max_request_body,omitempty"`

	// ReadTimeout caps how long the proxy takes to read a complete request
	// (headers plus body) for all routes. Accepts Go duration strings; empty
	// keeps the 30s default. Raise it when large uploads travel over slow
	// links, since the body must arrive within this window.
	ReadTimeout string `mapstructure:"read_timeout" yaml:"read_timeout,omitempty"`
}

// Hash returns a stable digest of the effective configuration. The control
// plane uses it for optimistic concurrency (If-Match) so a remote write cannot
// silently overwrite a local edit. Only the digest leaves the process.
func (c *Config) Hash() string {
	if c == nil {
		return ""
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// IsIPBlocked checks exact IPs and CIDR ranges from the security blacklist.
func (c *Config) IsIPBlocked(rawIP string) bool {
	ip, err := netip.ParseAddr(strings.TrimSpace(rawIP))
	if err != nil {
		return false
	}
	for _, entry := range c.Security.IPBlacklist {
		entry = strings.TrimSpace(entry)
		if prefix, err := netip.ParsePrefix(entry); err == nil && prefix.Contains(ip) {
			return true
		}
		if blocked, err := netip.ParseAddr(entry); err == nil && blocked == ip {
			return true
		}
	}
	return false
}

// DockerConfig configures container label discovery. When enabled, Nexo reads
// running containers and turns nexo.* labels into proxy routes, so a service
// needs no entry in this file.
type DockerConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	// Socket is the Docker daemon socket path.
	Socket string `mapstructure:"socket" yaml:"socket,omitempty"`
	// Host prefixes upstreams that are only reachable through a published host
	// port; it must be reachable from the Nexo process (e.g. 127.0.0.1 when Nexo
	// runs on the same host, the Docker gateway when it runs in a container).
	Host string `mapstructure:"host" yaml:"host,omitempty"`
}

// SecurityConfig represents security-related configuration
type SecurityConfig struct {
	RateLimitEnabled    bool     `mapstructure:"rate_limit_enabled" yaml:"rate_limit_enabled,omitempty"`
	RateLimitRequests   int      `mapstructure:"rate_limit_requests" yaml:"rate_limit_requests,omitempty"`
	RateLimitWindow     int      `mapstructure:"rate_limit_window" yaml:"rate_limit_window,omitempty"`
	MaxLoginAttempts    int      `mapstructure:"max_login_attempts" yaml:"max_login_attempts,omitempty"`
	LoginLockoutMinutes int      `mapstructure:"login_lockout_minutes" yaml:"login_lockout_minutes,omitempty"`
	IPBlacklist         []string `mapstructure:"ip_blacklist" yaml:"ip_blacklist,omitempty"`
}

// ControlPlaneConfig configures the node control API and, optionally, the
// coordinator role that observes other Nexo nodes.
type ControlPlaneConfig struct {
	Enabled     bool                  `mapstructure:"enabled" yaml:"enabled"`
	Listen      string                `mapstructure:"listen" yaml:"listen,omitempty"`
	Node        ControlNodeConfig     `mapstructure:"node" yaml:"node,omitempty"`
	Auth        ControlAuthConfig     `mapstructure:"auth" yaml:"auth,omitempty"`
	Coordinator CoordinatorConfig     `mapstructure:"coordinator" yaml:"coordinator,omitempty"`
	Topology    ControlTopologyConfig `mapstructure:"topology" yaml:"topology,omitempty"`
	TLS         ControlTLSConfig      `mapstructure:"tls" yaml:"tls,omitempty"`
}

// ControlTLSConfig secures the control listener. It is required when Listen is
// not a private or loopback address: plaintext management traffic is only
// acceptable inside a VPN/tailnet.
type ControlTLSConfig struct {
	CertFile string `mapstructure:"cert_file" yaml:"cert_file,omitempty"`
	KeyFile  string `mapstructure:"key_file" yaml:"key_file,omitempty"`
	// ClientCAFile enables mutual TLS: peers must present a certificate signed
	// by this CA in addition to their bearer token.
	ClientCAFile string `mapstructure:"client_ca_file" yaml:"client_ca_file,omitempty"`
}

// ControlNodeConfig carries the stable logical identity of this node. ID is
// generated once and persisted under base_dir when omitted; it must never be
// derived from a network address.
type ControlNodeConfig struct {
	ID     string            `mapstructure:"id" yaml:"id,omitempty"`
	Name   string            `mapstructure:"name" yaml:"name,omitempty"`
	Labels map[string]string `mapstructure:"labels" yaml:"labels,omitempty"`
}

// ControlAuthConfig points at the node token. The token file is re-read per
// request so rotation does not need a restart.
type ControlAuthConfig struct {
	// TokenFile grants read-only access. Required whenever Listen is not
	// loopback.
	TokenFile string `mapstructure:"token_file" yaml:"token_file,omitempty"`
	// WriteTokenFile grants command execution (route, certificate, security).
	// Keep it separate so read-only observers never hold write credentials.
	WriteTokenFile string `mapstructure:"write_token_file" yaml:"write_token_file,omitempty"`
}

// CoordinatorConfig turns this node into a coordinator that polls the listed
// peers. Durations accept Go duration strings.
type CoordinatorConfig struct {
	Enabled        bool                `mapstructure:"enabled" yaml:"enabled"`
	PollInterval   string              `mapstructure:"poll_interval" yaml:"poll_interval,omitempty"`
	RequestTimeout string              `mapstructure:"request_timeout" yaml:"request_timeout,omitempty"`
	StaleAfter     string              `mapstructure:"stale_after" yaml:"stale_after,omitempty"`
	Peers          []ControlPeerConfig `mapstructure:"peers" yaml:"peers,omitempty"`
}

// ControlPeerConfig describes one observed node. Every peer uses its own
// token: a shared token would make revocation all-or-nothing.
type ControlPeerConfig struct {
	ID             string `mapstructure:"id" yaml:"id"`
	Name           string `mapstructure:"name" yaml:"name,omitempty"`
	URL            string `mapstructure:"url" yaml:"url"`
	TokenFile      string `mapstructure:"token_file" yaml:"token_file,omitempty"`
	WriteTokenFile string `mapstructure:"write_token_file" yaml:"write_token_file,omitempty"`

	// CAFile replaces the system trust store for this peer.
	CAFile string `mapstructure:"ca_file" yaml:"ca_file,omitempty"`
	// ClientCertFile and ClientKeyFile enable mutual TLS towards the peer.
	ClientCertFile string `mapstructure:"client_cert_file" yaml:"client_cert_file,omitempty"`
	ClientKeyFile  string `mapstructure:"client_key_file" yaml:"client_key_file,omitempty"`
	// ServerName overrides the TLS name when the URL host is an address.
	ServerName string `mapstructure:"server_name" yaml:"server_name,omitempty"`
	// InsecureSkipVerify disables certificate verification. Development only.
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify" yaml:"insecure_skip_verify,omitempty"`
	// AllowInsecureHTTP permits plaintext HTTP to a non-private address. It
	// exists for tunnels that already provide encryption and is refused
	// otherwise.
	AllowInsecureHTTP bool `mapstructure:"allow_insecure_http" yaml:"allow_insecure_http,omitempty"`
}

// ControlTopologyConfig holds explicit cross-node links. Links are display and
// audit data: they never change how a route forwards traffic.
type ControlTopologyConfig struct {
	Links []ControlLinkConfig `mapstructure:"links" yaml:"links,omitempty"`
}

type ControlLinkConfig struct {
	ID       string              `mapstructure:"id" yaml:"id"`
	From     ControlLinkEndpoint `mapstructure:"from" yaml:"from"`
	To       ControlLinkEndpoint `mapstructure:"to" yaml:"to"`
	Relation string              `mapstructure:"relation" yaml:"relation,omitempty"`
	Labels   map[string]string   `mapstructure:"labels" yaml:"labels,omitempty"`
}

type ControlLinkEndpoint struct {
	NodeID  string `mapstructure:"node_id" yaml:"node_id"`
	RouteID string `mapstructure:"route_id" yaml:"route_id,omitempty"`
}

// AuthConfig represents OAuth authentication configuration
type AuthConfig struct {
	GitHub     GitHubAuthConfig `mapstructure:"github" yaml:"github,omitempty"`
	AuthHost   string           `mapstructure:"auth_host" yaml:"auth_host,omitempty"`     // Unified auth domain for OAuth callback
	SecretKey  string           `mapstructure:"secret_key" yaml:"secret_key,omitempty"`   // Secret key for signing tokens
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
	// Enabled serves the admin UI. Data-plane-only nodes can turn it off; the
	// control plane keeps working without it.
	Enabled  bool   `mapstructure:"enabled" yaml:"enabled"`
	Host     string `mapstructure:"host" yaml:"host,omitempty"`         // Bind host (default: 127.0.0.1)
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
	v.SetDefault("docker:enabled", false)
	v.SetDefault("docker:socket", "/var/run/docker.sock")
	v.SetDefault("docker:host", "127.0.0.1")
	v.SetDefault("webui.enabled", true)
	v.SetDefault("control_plane.enabled", false)
	v.SetDefault("control_plane.listen", "127.0.0.1:9090")
	v.SetDefault("control_plane.coordinator.enabled", false)
	v.SetDefault("control_plane.coordinator.poll_interval", "10s")
	v.SetDefault("control_plane.coordinator.request_timeout", "3s")
	v.SetDefault("control_plane.coordinator.stale_after", "30s")
	v.SetDefault("max_request_body", "10MB")
	v.SetDefault("read_timeout", "30s")

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
	if used := v.ConfigFileUsed(); used != "" {
		if err := os.Chmod(used, 0600); err != nil {
			return nil, fmt.Errorf("secure config file permissions: %v", err)
		}
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
