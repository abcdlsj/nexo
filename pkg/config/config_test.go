package config

import "testing"

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
