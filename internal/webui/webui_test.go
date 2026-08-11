package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func TestUpdateRoute(t *testing.T) {
	t.Parallel()
	originalDomain := "api.example.com"
	original := &proxy.Config{
		Upstream:              "http://127.0.0.1:9000",
		WriteTimeout:          "5m",
		ResponseHeaderTimeout: "15s",
		Retry:                 true,
		Portal:                &proxy.PortalConfig{Name: "Old API"},
	}
	cfg := &config.Config{Proxies: map[string]*proxy.Config{originalDomain: original}}
	handler := &Handler{configs: newConfigStore(cfg, t.TempDir()+"/config.yaml", nil)}
	form := url.Values{
		"original_domain":    {originalDomain},
		"domain":             {"api-v2.example.com"},
		"type":               {"proxy"},
		"upstream":           {"http://127.0.0.1:9100"},
		"auth":               {"on"},
		"portal_name":        {"Developer API"},
		"portal_description": {"Internal API"},
		"portal_kind":        {"api"},
		"portal_group":       {"workspace"},
		"portal_order":       {"12"},
		"portal_hidden":      {"on"},
	}
	request := httptest.NewRequest(http.MethodPost, "/proxies/update", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()

	handler.handleUpdateProxy(response, request)

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/proxies?message=Route+updated" {
		t.Fatalf("update response = %d %q", response.Code, response.Header().Get("Location"))
	}
	updatedConfig := handler.config()
	if _, exists := updatedConfig.Proxies[originalDomain]; exists {
		t.Fatal("original route remained after domain rename")
	}
	updated := updatedConfig.Proxies["api-v2.example.com"]
	if updated == nil {
		t.Fatal("renamed route was not created")
	}
	if updated.Upstream != "http://127.0.0.1:9100" || !updated.Auth {
		t.Fatalf("editable route fields were not updated: %+v", updated)
	}
	if updated.WriteTimeout != "5m" || updated.ResponseHeaderTimeout != "15s" || !updated.Retry {
		t.Fatalf("advanced route settings were lost: %+v", updated)
	}
	if updated.Portal == nil || updated.Portal.Name != "Developer API" || updated.Portal.Kind != "API" || updated.Portal.Order != 12 || !updated.Portal.Hidden {
		t.Fatalf("gateway directory settings were not updated: %+v", updated.Portal)
	}
}

func TestRouteCollision(t *testing.T) {
	t.Parallel()
	original := &proxy.Config{Upstream: "http://127.0.0.1:9000"}
	existing := &proxy.Config{Upstream: "http://127.0.0.1:9100"}
	cfg := &config.Config{Proxies: map[string]*proxy.Config{
		"api.example.com":   original,
		"taken.example.com": existing,
	}}
	handler := &Handler{configs: newConfigStore(cfg, t.TempDir()+"/config.yaml", nil)}
	form := url.Values{
		"original_domain": {"api.example.com"},
		"domain":          {"taken.example.com"},
		"type":            {"proxy"},
		"upstream":        {"http://127.0.0.1:9200"},
	}
	request := httptest.NewRequest(http.MethodPost, "/proxies/update", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()

	handler.handleUpdateProxy(response, request)

	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusSeeOther || location.Query().Get("error") != "domain_exists" {
		t.Fatalf("collision response = %d %q", response.Code, response.Header().Get("Location"))
	}
	current := handler.config()
	if current.Proxies["api.example.com"].Upstream != original.Upstream || current.Proxies["taken.example.com"].Upstream != existing.Upstream {
		t.Fatal("domain collision changed the route map")
	}
}

func TestBuildRoutes(t *testing.T) {
	t.Parallel()
	proxies := map[string]*proxy.Config{
		"docs.example.com": {Upstream: "http://docs:8080"},
		"api.example.com": {
			Upstream: "http://api:9000",
			Auth:     true,
			Portal:   &proxy.PortalConfig{Name: "Developer API", Description: "Internal API", Icon: "javascript:alert(1)", Group: "work", Order: 20},
		},
		"studio.example.com": {
			Upstream: "http://studio:4173",
			Portal:   &proxy.PortalConfig{Name: "Studio", Icon: "/assets/studio.svg", Order: 10},
		},
		"hidden.example.com": {Upstream: "http://hidden:80", Portal: &proxy.PortalConfig{Hidden: true}},
	}

	routes := buildRouteViews(proxies)
	if len(routes) != 3 {
		t.Fatalf("buildRouteViews() returned %d routes", len(routes))
	}
	wantDomains := []string{"studio.example.com", "api.example.com", "docs.example.com"}
	for i, want := range wantDomains {
		if routes[i].Domain != want {
			t.Errorf("route %d domain = %q, want %q", i, routes[i].Domain, want)
		}
	}
	if routes[0].IconURL != "/assets/studio.svg" || routes[0].Name != "Studio" {
		t.Errorf("custom portal metadata not applied: %+v", routes[0])
	}
	if routes[1].IconURL != "" || routes[1].Policy != "OAUTH" {
		t.Errorf("unsafe icon was not replaced or policy is wrong: %+v", routes[1])
	}
	if routes[2].Name != "Docs" || routes[2].Initial != "D" {
		t.Errorf("default display metadata is wrong: %+v", routes[2])
	}
	if routes[2].Description != "" {
		t.Errorf("default route retained generated description: %q", routes[2].Description)
	}
}

func TestHiddenRoutes(t *testing.T) {
	t.Parallel()
	proxies := map[string]*proxy.Config{
		"root.example.com":    {Redirect: "https://github.com/example"},
		"legacy.example.com":  {Redirect: "https://app.example.com", Portal: &proxy.PortalConfig{Name: "Legacy"}},
		"service.example.com": {Upstream: "http://service:8080"},
		"example.com":         {Upstream: "http://website:8080"},
		"published.com":       {Upstream: "http://website:8080", Portal: &proxy.PortalConfig{Name: "Published"}},
	}

	routes := buildRouteViews(proxies)
	if len(routes) != 3 {
		t.Fatalf("buildRouteViews() returned %d routes, want 3", len(routes))
	}
	for _, route := range routes {
		if route.Domain == "root.example.com" || route.Domain == "example.com" {
			t.Fatalf("implicit redirect or apex domain was published: %s", route.Domain)
		}
	}
}

func TestApexDomain(t *testing.T) {
	t.Parallel()
	if !isApexDomain("songjian.li") {
		t.Fatal("songjian.li should be recognized as an apex domain")
	}
	if isApexDomain("api.songjian.li") || isApexDomain("service.local") {
		t.Fatal("subdomains and non-public local names must not be treated as public apex domains")
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
	routes := buildRouteViewsWithDiscovery(
		map[string]*proxy.Config{"app.example.com": cfg},
		map[string]routeDiscoveryResult{"app.example.com": result},
	)
	if len(routes) != 1 || routes[0].IconURL != "/api/route-icon?domain=app.example.com" {
		t.Fatalf("discovered icon was not exposed through the route icon endpoint: %+v", routes)
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
	for _, path := range []string{"/", "/proxies", "/certs", "/traffic", "/config", "/login"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s returned %d: %s", path, w.Code, w.Body.String())
		}
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
