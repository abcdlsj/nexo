package webui

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abcdlsj/nexo/pkg/config"
	"github.com/abcdlsj/nexo/pkg/proxy"
)

func TestSafeLocalRedirect(t *testing.T) {
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

func TestClientIPIgnoresUntrustedForwardingHeaders(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "http://localhost/login", nil)
	r.RemoteAddr = "192.0.2.10:4321"
	r.Header.Set("X-Forwarded-For", "203.0.113.5")
	r.Header.Set("X-Real-IP", "203.0.113.6")
	if got := getClientIP(r); got != "192.0.2.10" {
		t.Fatalf("getClientIP() = %q", got)
	}
}

func TestSecurityMiddlewareHeaders(t *testing.T) {
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

func TestAllPagesRenderSelfContainedHTML(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	page := PageData{Config: cfg, CSRFToken: "test-token", CurrentIP: "127.0.0.1"}
	login := struct {
		PageData
		Error    string
		Redirect string
		Locked   bool
		LockTime int
	}{PageData: page, Redirect: "/"}
	pages := map[string]any{
		"404.html":       page,
		"dashboard.html": DashboardData{PageData: page},
		"proxies.html":   ProxiesData{PageData: page},
		"certs.html":     CertsData{PageData: page},
		"config.html":    ConfigData{PageData: page},
		"traffic.html":   page,
		"login.html":     login,
	}
	for name, data := range pages {
		var output bytes.Buffer
		if err := tmpl.ExecuteTemplate(&output, name, data); err != nil {
			t.Fatalf("render %s: %v", name, err)
		}
		html := output.String()
		if !strings.Contains(html, "<!DOCTYPE html>") || !strings.Contains(html, "</html>") {
			t.Errorf("%s did not render a complete document", name)
		}
		if strings.Contains(html, "fonts.googleapis.com") || strings.Contains(html, "fonts.gstatic.com") {
			t.Errorf("%s contains an external font dependency", name)
		}
	}
}

func TestBuildRouteViewsUsesPortalMetadataAndStableOrder(t *testing.T) {
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
	if routes[1].IconURL != "https://api.example.com/favicon.ico" || routes[1].Policy != "OAUTH" {
		t.Errorf("unsafe icon was not replaced or policy is wrong: %+v", routes[1])
	}
	if routes[2].Name != "Docs" || routes[2].Initial != "D" {
		t.Errorf("default display metadata is wrong: %+v", routes[2])
	}
}

func TestDashboardRendersSharedRouteProtocol(t *testing.T) {
	t.Parallel()
	page := PageData{Config: &config.Config{}, CurrentIP: "127.0.0.1"}
	data := DashboardData{PageData: page, Routes: []RouteView{{Domain: "api.example.com", Name: "Developer API", Description: "Internal API", IconURL: "https://api.example.com/favicon.ico", Initial: "D", Kind: "PROXY", Policy: "OAUTH", Href: "https://api.example.com", Auth: true}}, ProtectedRoutes: 1}
	var output bytes.Buffer
	if err := tmpl.ExecuteTemplate(&output, "dashboard.html", data); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	for _, value := range []string{"ROUTING BOARD", "ROUTE DIRECTORY", "Developer API", "data-route-index=\"0\"", "class=\"app-page\""} {
		if !strings.Contains(html, value) {
			t.Errorf("dashboard output missing %q", value)
		}
	}
	for _, removed := range []string{"Control room", "System overview", "All systems operational"} {
		if strings.Contains(html, removed) {
			t.Errorf("dashboard output retained removed copy %q", removed)
		}
	}
}

func TestMaskSensitiveConfigParsesYAML(t *testing.T) {
	t.Parallel()
	raw := "cloudflare:\n  \"api_token\" : token-value\nauth:\n  github:\n    client_secret: oauth-value\nwebui:\n  password: bcrypt-value\nemail: visible@example.com\n"
	masked := maskSensitiveConfig(raw)
	for _, secret := range []string{"token-value", "oauth-value", "bcrypt-value"} {
		if strings.Contains(masked, secret) {
			t.Errorf("masked config leaked %q: %s", secret, masked)
		}
	}
	if !strings.Contains(masked, "visible@example.com") {
		t.Fatal("masking removed a non-sensitive value")
	}
}

func TestPreviewPages(t *testing.T) {
	t.Parallel()
	handler := newPreviewHandler()
	for _, path := range []string{"/", "/proxies", "/certs", "/traffic", "/config", "/login"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s returned %d: %s", path, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "<!DOCTYPE html>") {
			t.Errorf("GET %s did not return HTML", path)
		}
	}

	r := httptest.NewRequest(http.MethodGet, "/api/traffic", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "api.nexo.local") {
		t.Fatalf("traffic fixture response = %d %s", w.Code, w.Body.String())
	}

	r = httptest.NewRequest(http.MethodGet, "/favicon.svg", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "image/svg+xml" || !strings.Contains(w.Body.String(), "<svg") {
		t.Fatalf("favicon response = %d %q %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
}
