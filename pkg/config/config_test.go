package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func TestIsIPBlocked(t *testing.T) {
	t.Parallel()
	cfg := &Config{Security: SecurityConfig{IPBlacklist: []string{"192.0.2.4", "2001:db8::/32"}}}
	for _, ip := range []string{"192.0.2.4", "2001:db8::5"} {
		if !cfg.IsIPBlocked(ip) {
			t.Errorf("expected %s to be blocked", ip)
		}
	}
	for _, ip := range []string{"192.0.2.5", "invalid"} {
		if cfg.IsIPBlocked(ip) {
			t.Errorf("expected %s to be allowed", ip)
		}
	}
}

func TestAdvancedProxyFieldsYAML(t *testing.T) {
	t.Parallel()
	raw := []byte(`response_header_timeout: 5m
proxies:
  api.example.com:
    upstream: http://127.0.0.1:9000
    response_header_timeout: 10s
    cache: false
`)
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.ResponseHeaderTimeout != "5m" {
		t.Fatalf("top-level response_header_timeout = %q", cfg.ResponseHeaderTimeout)
	}
	route := cfg.Proxies["api.example.com"]
	if route == nil || route.ResponseHeaderTimeout != "10s" {
		t.Fatalf("route response_header_timeout not decoded: %+v", route)
	}
	if route.Cache == nil || *route.Cache {
		t.Fatalf("route cache: false not decoded: %+v", route)
	}
	var defaultCfg Config
	if !defaultCfg.Proxies["missing"].CacheEnabled() {
		t.Fatal("nil cache should default to enabled")
	}

	encoded, err := yaml.Marshal(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip Config
	if err := yaml.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	roundTripRoute := roundTrip.Proxies["api.example.com"]
	if roundTrip.ResponseHeaderTimeout != cfg.ResponseHeaderTimeout || roundTripRoute == nil || roundTripRoute.Cache == nil || *roundTripRoute.Cache {
		t.Fatalf("advanced proxy fields changed after round trip: %s", encoded)
	}
}

func TestAdvancedProxyFieldsViper(t *testing.T) {
	t.Parallel()
	v := viper.NewWithOptions(viper.KeyDelimiter(":"))
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader("response_header_timeout: 5m\nproxies:\n  api.example.com:\n    upstream: http://127.0.0.1:9000\n    cache: false\n")); err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.ResponseHeaderTimeout != "5m" {
		t.Fatalf("top-level response_header_timeout = %q", cfg.ResponseHeaderTimeout)
	}
	route := cfg.Proxies["api.example.com"]
	if route == nil || route.Cache == nil || *route.Cache {
		t.Fatalf("route cache: false not decoded through viper: %+v", route)
	}
}
