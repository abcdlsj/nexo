package webui

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/abcdlsj/nexo/pkg/config"
	"github.com/abcdlsj/nexo/pkg/proxy"
	"github.com/abcdlsj/nexo/pkg/traffic"
)

// StartPreview serves the real templates with fake data on a loopback address.
// It intentionally does not read config, acquire certificates, or start :443.
func StartPreview(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid preview address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("preview must listen on loopback, got %q", host)
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           newPreviewHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	return server.ListenAndServe()
}

func newPreviewHandler() http.Handler {
	cfg, proxies, certs, trafficData := previewFixtures()
	security := (&Handler{cfg: cfg}).securityMiddleware
	mux := http.NewServeMux()

	render := func(w http.ResponseWriter, name string, data any, status int) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
			http.Error(w, "Preview render failed", http.StatusInternalServerError)
		}
	}
	page := func(active string) PageData {
		return PageData{ActiveNav: active, Config: cfg, CSRFToken: "preview-token", Demo: true}
	}

	mux.HandleFunc("/api/traffic", security(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(trafficData)
	}))
	mux.HandleFunc("/favicon.ico", security((&Handler{cfg: cfg}).handleFavicon))
	mux.HandleFunc("/favicon.svg", security((&Handler{cfg: cfg}).handleFavicon))
	mux.HandleFunc("/api/route-icon", security((&Handler{cfg: cfg}).handleRouteIcon))
	mux.HandleFunc("/", security(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			target := "/"
			switch {
			case strings.HasPrefix(r.URL.Path, "/proxies"):
				target = "/proxies"
			case strings.HasPrefix(r.URL.Path, "/certs"):
				target = "/certs"
			case strings.HasPrefix(r.URL.Path, "/config"):
				target = "/config"
			}
			http.Redirect(w, r, target+"?message=Preview+mode%3A+no+changes+were+saved", http.StatusSeeOther)
			return
		}
		switch r.URL.Path {
		case "/":
			routes := buildRouteViews(proxies)
			for index := range routes {
				if routes[index].Domain == "metrics.nexo.local" {
					routes[index].Unavailable = true
				}
			}
			data := DashboardData{PageData: page("dashboard"), Routes: routes, ProtectedRoutes: 2}
			render(w, "dashboard.html", data, http.StatusOK)
		case "/proxies":
			render(w, "proxies.html", ProxiesData{PageData: page("proxies"), Proxies: proxies}, http.StatusOK)
		case "/certs":
			render(w, "certs.html", CertsData{PageData: page("certs"), Wildcards: cfg.Wildcards, Certs: certs, LastRenewal: "2026-07-27 09:42:18"}, http.StatusOK)
		case "/config":
			render(w, "config.html", ConfigData{PageData: page("config"), MaskedAPIToken: "••••A9K2", RawConfig: previewRawConfig}, http.StatusOK)
		case "/traffic":
			render(w, "traffic.html", page("traffic"), http.StatusOK)
		case "/login":
			data := struct {
				PageData
				Error    string
				Redirect string
				Locked   bool
				LockTime int
			}{PageData: page(""), Redirect: "/"}
			render(w, "login.html", data, http.StatusOK)
		case "/404":
			render(w, "404.html", page(""), http.StatusNotFound)
		default:
			render(w, "404.html", page(""), http.StatusNotFound)
		}
	}))
	return mux
}

func previewFixtures() (*config.Config, map[string]*proxy.Config, []CertInfo, *traffic.TrafficData) {
	proxies := map[string]*proxy.Config{
		"api.nexo.local":     {Upstream: "http://127.0.0.1:9001", Auth: true, Portal: &proxy.PortalConfig{Name: "Developer API", Description: "Internal API and developer console", Kind: "API", Group: "workspace", Order: 20}},
		"studio.nexo.local":  {Upstream: "http://127.0.0.1:4173", Portal: &proxy.PortalConfig{Name: "Studio", Description: "Content, assets and publishing", Kind: "WEBSITE", Group: "workspace", Order: 10}},
		"metrics.nexo.local": {Upstream: "http://prometheus:9090", Auth: true, Portal: &proxy.PortalConfig{Name: "Observability", Description: "Metrics, logs and alerts", Kind: "SERVICE", Group: "system", Order: 30}},
		"old.nexo.local":     {Redirect: "https://studio.nexo.local", Portal: &proxy.PortalConfig{Name: "Legacy Studio", Description: "Redirect to Studio", Group: "system", Order: 40}},
	}
	cfg := &config.Config{
		Email:      "ops@nexo.local",
		BaseDir:    "/var/lib/nexo",
		CertDir:    "/var/lib/nexo/certs",
		Wildcards:  []string{"*.nexo.local"},
		Proxies:    proxies,
		Cloudflare: config.CloudflareConfig{APIToken: "preview-token"},
		Auth: config.AuthConfig{
			AuthHost: "auth.nexo.local",
			GitHub:   config.GitHubAuthConfig{ClientID: "preview-client", AllowedUsers: []string{"octocat", "nexo-ops"}},
		},
		Security: config.SecurityConfig{RateLimitEnabled: true, RateLimitRequests: 120, RateLimitWindow: 60, MaxLoginAttempts: 5, LoginLockoutMinutes: 30},
	}
	certs := []CertInfo{
		{Domain: "*.nexo.local", Status: "valid", ExpiryDate: "2026-10-19", DaysLeft: 84, Issuer: "Let's Encrypt R12"},
		{Domain: "api.nexo.local", Status: "valid", ExpiryDate: "2026-10-19", DaysLeft: 84, Issuer: "Let's Encrypt R12", UsesWildcard: true, WildcardDomain: "*.nexo.local"},
		{Domain: "studio.nexo.local", Status: "expiring", ExpiryDate: "2026-08-04", DaysLeft: 8, Issuer: "Let's Encrypt R11", UsesWildcard: true, WildcardDomain: "*.nexo.local"},
		{Domain: "legacy.example.net", Status: "error", ExpiryDate: "2026-07-20", DaysLeft: -7, Issuer: "Let's Encrypt E6"},
	}
	now := time.Now()
	records := []traffic.RequestRecord{
		{Timestamp: now.Add(-4 * time.Second), Domain: "api.nexo.local", IP: "192.0.2.42", Method: "GET", Path: "/v1/projects?limit=20", StatusCode: 200, IsHTTPS: true},
		{Timestamp: now.Add(-12 * time.Second), Domain: "studio.nexo.local", IP: "198.51.100.8", Method: "GET", Path: "/assets/editor.js", StatusCode: 304, IsHTTPS: true},
		{Timestamp: now.Add(-21 * time.Second), Domain: "api.nexo.local", IP: "203.0.113.17", Method: "POST", Path: "/v1/deployments", StatusCode: 201, IsHTTPS: true},
		{Timestamp: now.Add(-39 * time.Second), Domain: "metrics.nexo.local", IP: "192.0.2.91", Method: "GET", Path: "/search?q=<script>alert(1)</script>", StatusCode: 200, IsHTTPS: true},
		{Timestamp: now.Add(-55 * time.Second), Domain: "old.nexo.local", IP: "198.51.100.31", Method: "GET", Path: "/docs", StatusCode: 307, IsHTTPS: false},
	}
	stats := map[string]*traffic.DomainStats{
		"api.nexo.local":     {Domain: "api.nexo.local", Requests: 18420, HTTPSCount: 18420, UniqueIPCount: 127},
		"studio.nexo.local":  {Domain: "studio.nexo.local", Requests: 9304, HTTPSCount: 9298, UniqueIPCount: 64},
		"metrics.nexo.local": {Domain: "metrics.nexo.local", Requests: 4217, HTTPSCount: 4217, UniqueIPCount: 12},
		"old.nexo.local":     {Domain: "old.nexo.local", Requests: 814, HTTPSCount: 772, UniqueIPCount: 203},
	}
	trafficData := &traffic.TrafficData{Records: records, DomainStats: stats, TotalReqs: 32755, HTTPSReqs: 32707, UniqueIPCount: 386, LastSaved: now.Add(-2 * time.Minute)}
	return cfg, proxies, certs, trafficData
}

const previewRawConfig = `email: ops@nexo.local
base_dir: /var/lib/nexo
cert_dir: /var/lib/nexo/certs
cloudflare:
  api_token: "••••••••"
wildcards:
  - "*.nexo.local"
webui:
  host: 127.0.0.1
  port: "8080"
security:
  rate_limit_enabled: true
  rate_limit_requests: 120
`
