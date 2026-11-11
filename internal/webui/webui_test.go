package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/abcdlsj/nexo/pkg/config"
	"github.com/abcdlsj/nexo/pkg/proxy"
	"github.com/abcdlsj/nexo/pkg/traffic"
	"gopkg.in/yaml.v3"
)

func TestRedirect(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"":                          "/",
		"/traffic?range=recent":     "/traffic?range=recent",
		"https://evil.example/x":    "/",
		"//evil.example/x":          "/",
		"javascript://evil.example": "/",
	}
	for input, want := range tests {
		if got := safeLocalRedirect(input); got != want {
			t.Errorf("safeLocalRedirect(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestValidation(t *testing.T) {
	t.Parallel()
	for _, domain := range []string{"example.com", "api.example.com"} {
		if !validDomain(domain, false) {
			t.Errorf("expected valid domain %q", domain)
		}
	}
	for _, domain := range []string{"../secret", "-bad.example", "example", "*.example.com"} {
		if validDomain(domain, false) {
			t.Errorf("expected invalid domain %q", domain)
		}
	}
	if !validDomain("*.example.com", true) || validDomain("example.com", true) {
		t.Fatal("wildcard validation mismatch")
	}
	if !validHTTPURL("http://127.0.0.1:8080") || !validHTTPURL("https://example.com/path") {
		t.Fatal("expected HTTP URLs to be accepted")
	}
	for _, raw := range []string{"javascript://example.com", "https://user:pass@example.com", "//example.com"} {
		if validHTTPURL(raw) {
			t.Errorf("expected invalid URL %q", raw)
		}
	}
}

func TestClientIP(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "http://localhost/login", nil)
	r.RemoteAddr = "192.0.2.10:4321"
	r.Header.Set("X-Forwarded-For", "203.0.113.5")
	r.Header.Set("X-Real-IP", "203.0.113.6")
	if got := getClientIP(r); got != "192.0.2.10" {
		t.Fatalf("getClientIP() = %q", got)
	}
}

func TestSecurityHeaders(t *testing.T) {
	t.Parallel()
	h := &Handler{}
	r := httptest.NewRequest("GET", "http://localhost/", nil)
	w := httptest.NewRecorder()
	h.securityMiddleware(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })(w, r)
	for _, header := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Permissions-Policy"} {
		if w.Header().Get(header) == "" {
			t.Errorf("missing security header %s", header)
		}
	}
}

func TestDiscoveryIconCache(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><head><link rel="icon" href="/static/icon.svg"></head></html>`))
		case "/static/icon.svg":
			w.Header().Set("Content-Type", "image/svg+xml")
			_, _ = w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	discoverer := newRouteDiscoverer()
	cfg := &proxy.Config{Upstream: server.URL}
	result := discoverer.discover(context.Background(), "app.example.com", cfg)
	if result.Kind != "WEBSITE" || result.IconContentType != "image/svg+xml" || len(result.Icon) == 0 {
		t.Fatalf("unexpected discovery result: %+v", result)
	}
	before := requests.Load()
	result = discoverer.discover(context.Background(), "app.example.com", cfg)
	if result.Kind != "WEBSITE" || requests.Load() != before {
		t.Fatalf("cached discovery made another upstream request: before=%d after=%d", before, requests.Load())
	}
}

func TestDiscoveryAPI(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"service":"payments"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	result := newRouteDiscoverer().discover(context.Background(), "api.example.com", &proxy.Config{Upstream: server.URL})
	if result.Kind != "API" {
		t.Fatalf("JSON upstream classified as %q, want API", result.Kind)
	}
}

func TestDiscoveryHTTPFailure(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "maintenance", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	result := newRouteDiscoverer().discover(context.Background(), "down.example.com", &proxy.Config{Upstream: server.URL})
	if !result.Unavailable {
		t.Fatal("503 upstream was not marked unavailable")
	}
}

func TestDiscoveryDialFailure(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	upstream := server.URL
	server.Close()

	result := newRouteDiscoverer().discover(context.Background(), "offline.example.com", &proxy.Config{Upstream: upstream})
	if !result.Unavailable {
		t.Fatal("connection failure was not marked unavailable")
	}
}

func TestUnknownRouteIcon(t *testing.T) {
	t.Parallel()
	handler := &Handler{configs: newConfigStore(&config.Config{Proxies: map[string]*proxy.Config{}}, "", nil)}
	request := httptest.NewRequest(http.MethodGet, "/api/route-icon?domain=unknown.example.com", nil)
	response := httptest.NewRecorder()
	handler.handleRouteIcon(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown icon domain returned %d", response.Code)
	}
}

func TestMissingRouteIcon(t *testing.T) {
	t.Parallel()
	handler := &Handler{configs: newConfigStore(&config.Config{Proxies: map[string]*proxy.Config{
		"api.example.com": {Upstream: "http://127.0.0.1:9000", Portal: &proxy.PortalConfig{Kind: "API"}},
	}}, "", nil)}
	request := httptest.NewRequest(http.MethodGet, "/api/route-icon?domain=api.example.com", nil)
	response := httptest.NewRecorder()
	handler.handleRouteIcon(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("route without discovered icon returned %d, want 404", response.Code)
	}
}

func TestMaskConfig(t *testing.T) {
	t.Parallel()
	raw := "cloudflare:\n  \"api_token\" : token-value\nauth:\n  github:\n    client_secret: oauth-value\nwebui:\n  password: bcrypt-value\nemail: visible@example.com\n"
	masked := maskSensitiveConfig(raw)
	var got config.Config
	if err := yaml.Unmarshal([]byte(masked), &got); err != nil {
		t.Fatal(err)
	}
	if got.Cloudflare.APIToken != "••••••••" || got.Auth.GitHub.ClientSecret != "••••••••" || got.WebUI.Password != "••••••••" {
		t.Fatalf("sensitive values were not masked: %+v", got)
	}
	if got.Email != "visible@example.com" {
		t.Fatalf("email = %q, want visible value", got.Email)
	}
}

func TestPreview(t *testing.T) {
	t.Parallel()
	handler := newPreviewHandler()
	for _, path := range []string{"/fleet", "/certs", "/traffic", "/config", "/login"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s returned %d: %s", path, w.Code, w.Body.String())
		}
	}

	rootRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	rootResponse := httptest.NewRecorder()
	handler.ServeHTTP(rootResponse, rootRequest)
	if rootResponse.Code != http.StatusSeeOther || rootResponse.Header().Get("Location") != "/fleet" {
		t.Fatalf("root should redirect to fleet, got %d %q", rootResponse.Code, rootResponse.Header().Get("Location"))
	}

	r := httptest.NewRequest(http.MethodGet, "/404", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("404 response = %d %s", w.Code, w.Body.String())
	}

	r = httptest.NewRequest(http.MethodGet, "/api/traffic", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	var data traffic.TrafficData
	if err := json.NewDecoder(w.Body).Decode(&data); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || data.DomainStats["api.nexo.local"] == nil {
		t.Fatalf("traffic fixture response = %d %s", w.Code, w.Body.String())
	}

	r = httptest.NewRequest(http.MethodGet, "/favicon.svg", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "image/svg+xml" {
		t.Fatalf("favicon response = %d %q %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
}

func TestParseAuthExclude(t *testing.T) {
	t.Parallel()
	got := parseAuthExclude(" /manifest.webmanifest , /icon-*.png,, /manifest.webmanifest ")
	want := []string{"/manifest.webmanifest", "/icon-*.png"}
	if len(got) != len(want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}

	if paths := parseAuthExclude("  "); len(paths) != 0 {
		t.Fatalf("expected empty list, got %#v", paths)
	}
}
