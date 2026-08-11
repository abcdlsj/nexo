package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestPortalConfigYAMLRoundTrip(t *testing.T) {
	t.Parallel()
	raw := []byte("upstream: http://127.0.0.1:8080\nportal:\n  name: Studio\n  description: Publishing\n  icon: auto\n  group: workspace\n  order: 10\n")
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Portal == nil || cfg.Portal.Name != "Studio" || cfg.Portal.Order != 10 {
		t.Fatalf("portal config not decoded: %+v", cfg.Portal)
	}
	encoded, err := yaml.Marshal(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || !strings.Contains(string(encoded), "portal:") {
		t.Fatalf("portal config not encoded: %s", encoded)
	}
}

func TestCheckTargetOnlyAllowsSafeHTTPURLs(t *testing.T) {
	t.Parallel()
	valid, _ := url.Parse("https://upstream.example/path")
	if err := CheckTarget(valid); err != nil {
		t.Fatalf("valid target rejected: %v", err)
	}
	for _, raw := range []string{"file:///etc/passwd", "https://user:pass@example.com", "/relative"} {
		target, _ := url.Parse(raw)
		if err := CheckTarget(target); err == nil {
			t.Errorf("unsafe target accepted: %s", raw)
		}
	}
}

func TestCacheHeadersDoNotExposePrivateResponses(t *testing.T) {
	t.Parallel()
	request := &http.Request{URL: &url.URL{Path: "/account.js"}, Header: make(http.Header)}
	response := &http.Response{Request: request, Header: make(http.Header)}
	response.Header.Set("Set-Cookie", "session=secret")
	setCacheHeaders(response)
	if got := response.Header.Get("Cache-Control"); got != noCache {
		t.Fatalf("cookie response cache policy = %q", got)
	}

	response = &http.Response{Request: request, Header: make(http.Header)}
	response.Header.Set("Cache-Control", "private, max-age=60")
	setCacheHeaders(response)
	if got := response.Header.Get("Cache-Control"); got != "private, max-age=60" {
		t.Fatalf("upstream cache policy overwritten: %q", got)
	}
}

func TestParseDurationSetting(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		raw      string
		fallback time.Duration
		want     time.Duration
	}{
		{name: "empty uses fallback", raw: "", fallback: 30 * time.Second, want: 30 * time.Second},
		{name: "explicit zero", raw: "0", fallback: 30 * time.Second, want: 0},
		{name: "duration string", raw: "5m", fallback: 30 * time.Second, want: 5 * time.Minute},
		{name: "invalid falls back", raw: "soon", fallback: 30 * time.Second, want: 30 * time.Second},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ParseDuration(tc.raw, tc.fallback); got != tc.want {
				t.Fatalf("ParseDuration(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestNewAppliesResponseHeaderTimeout(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  string
		want time.Duration
	}{
		{name: "default", raw: "", want: 30 * time.Second},
		{name: "disabled", raw: "0", want: 0},
		{name: "long first byte", raw: "5m", want: 5 * time.Minute},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &Config{Upstream: "http://127.0.0.1:1", ResponseHeaderTimeout: tc.raw}
			h := New(cfg, "example.test")
			if h == nil {
				t.Fatal("New returned nil handler")
			}
			tr, ok := h.proxy.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("unexpected transport type %T", h.proxy.Transport)
			}
			if tr.ResponseHeaderTimeout != tc.want {
				t.Fatalf("ResponseHeaderTimeout = %v, want %v", tr.ResponseHeaderTimeout, tc.want)
			}
		})
	}
}

func TestShouldRetryUpstream(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		method string
		err    error
		want   bool
	}{
		{name: "get with transport error", method: http.MethodGet, err: errors.New("dial tcp: connection refused"), want: true},
		{name: "head with transport error", method: http.MethodHead, err: errors.New("dial tcp: connection refused"), want: true},
		{name: "options with transport error", method: http.MethodOptions, err: errors.New("dial tcp: connection refused"), want: true},
		{name: "post never retries", method: http.MethodPost, err: errors.New("dial tcp: connection refused"), want: false},
		{name: "canceled never retries", method: http.MethodGet, err: context.Canceled, want: false},
		{name: "deadline never retries", method: http.MethodGet, err: context.DeadlineExceeded, want: false},
		{name: "nil error never retries", method: http.MethodGet, err: nil, want: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, err := http.NewRequestWithContext(context.Background(), tc.method, "http://example.test/", nil)
			if err != nil {
				t.Fatalf("failed to build request: %v", err)
			}
			if got := shouldRetryUpstream(req, tc.err); got != tc.want {
				t.Fatalf("shouldRetryUpstream(%s, %v) = %v, want %v", tc.method, tc.err, got, tc.want)
			}
		})
	}
}

func TestConfigChangedIncludesTimeoutSettings(t *testing.T) {
	t.Parallel()
	cfg := &Config{Upstream: "http://127.0.0.1:1"}
	h := New(cfg, "example.test")
	if h == nil {
		t.Fatal("New returned nil handler")
	}
	if h.ConfigChanged(&Config{Upstream: "http://127.0.0.1:1"}) {
		t.Fatal("identical config reported as changed")
	}
	if !h.ConfigChanged(&Config{Upstream: "http://127.0.0.1:1", WriteTimeout: "5m"}) {
		t.Fatal("write_timeout change not detected")
	}
	if !h.ConfigChanged(&Config{Upstream: "http://127.0.0.1:1", ResponseHeaderTimeout: "0"}) {
		t.Fatal("response_header_timeout change not detected")
	}
	if !h.ConfigChanged(&Config{Upstream: "http://127.0.0.1:1", Retry: true}) {
		t.Fatal("retry change not detected")
	}
}
