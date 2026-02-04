package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/log"
)

const (
	// Cache durations
	longTermCache  = "public, max-age=86400, stale-while-revalidate=3600" // 1 day, stale 1 hour
	shortTermCache = "public, max-age=300, stale-while-revalidate=60"     // 5 mins, stale 1 min
	noCache        = "no-cache, no-store, must-revalidate"

	// File extensions and content types that should use long-term caching
	staticExtensions = ".css,.js,.woff,.woff2,.ttf,.eot"
	staticPrefixes   = "image/,video/,audio/"
)

// Config represents the configuration for a proxy
type Config struct {
	Upstream string `mapstructure:"upstream" yaml:"upstream,omitempty"`
	Redirect string `mapstructure:"redirect" yaml:"redirect,omitempty"`
	Auth     bool   `mapstructure:"auth" yaml:"auth,omitempty"` // Enable OAuth authentication for this proxy
}

// Handler represents a proxy handler
type Handler struct {
	proxy    *httputil.ReverseProxy
	redirect string
	upstream string
	host     string
}

// ConfigChanged checks if the configuration has changed
func (h *Handler) ConfigChanged(newCfg *Config) bool {
	if h.redirect != "" {
		return h.redirect != newCfg.Redirect
	}
	return h.upstream != newCfg.Upstream
}

// New creates a new proxy handler
func New(cfg *Config, host string) *Handler {
	if cfg.Redirect != "" {
		return &Handler{
			redirect: cfg.Redirect,
			host:     host,
		}
	}

	target, err := url.Parse(cfg.Upstream)
	if err != nil {
		log.Error("Failed to parse upstream URL", "domain", host, "err", err)
		return nil
	}

	p := httputil.NewSingleHostReverseProxy(target)
	p.Director = createDirector(p.Director)
	p.ModifyResponse = createResponseModifier(target, host)
	p.ErrorHandler = createErrorHandler(host)

	return &Handler{
		proxy:    p,
		upstream: cfg.Upstream,
		host:     host,
	}
}

// EnsureSchema ensures the URL has a valid scheme (http:// or https://)
func EnsureSchema(target string) string {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return "https://" + target
	}
	return target
}

// ServeHTTP implements the http.Handler interface
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.redirect != "" {
		http.Redirect(w, r, EnsureSchema(h.redirect), http.StatusTemporaryRedirect)
		return
	}
	h.proxy.ServeHTTP(w, r)
}

func createDirector(orig func(*http.Request)) func(*http.Request) {
	return func(r *http.Request) {
		orig(r)
		r.Header.Set("X-Forwarded-Host", r.Host)
		r.Header.Set("X-Forwarded-Proto", "https")
		if _, ok := r.Header["User-Agent"]; !ok {
			r.Header.Set("User-Agent", "")
		}
	}
}

func createResponseModifier(target *url.URL, domain string) func(*http.Response) error {
	return func(r *http.Response) error {
		if err := handleRedirect(r, target, domain); err != nil {
			return err
		}
		setCacheHeaders(r)
		return nil
	}
}

func handleRedirect(r *http.Response, target *url.URL, domain string) error {
	if r.StatusCode < 300 || r.StatusCode > 399 {
		return nil
	}

	loc := r.Header.Get("Location")
	if loc == "" {
		return nil
	}

	u, err := url.Parse(loc)
	if err != nil {
		return err
	}

	if u.Host == target.Host {
		u.Host = domain
		u.Scheme = "https"
		r.Header.Set("Location", u.String())
	}

	return nil
}

func createErrorHandler(host string) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		log.Error("Proxy error", "domain", host, "err", err)
		http.Error(w, "Proxy Error", http.StatusBadGateway)
	}
}

func setCacheHeaders(r *http.Response) {
	ct := r.Header.Get("Content-Type")
	ext := strings.ToLower(filepath.Ext(r.Request.URL.Path))

	isStatic := func() bool {
		if ext == "" {
			return false
		}
		for _, p := range strings.Split(staticPrefixes, ",") {
			if strings.HasPrefix(ct, p) {
				return true
			}
		}
		return strings.Contains(staticExtensions, ext)
	}

	isDynamic := func() bool {
		return strings.HasPrefix(ct, "text/html") ||
			strings.HasPrefix(ct, "application/json")
	}

	switch {
	case isDynamic():
		r.Header.Set("Cache-Control", noCache)
		r.Header.Set("Pragma", "no-cache")
		r.Header.Set("Expires", "0")
	case isStatic():
		r.Header.Set("Cache-Control", longTermCache)
	default:
		r.Header.Set("Cache-Control", shortTermCache)
	}
	r.Header.Set("Vary", "Accept-Encoding")
}

// CheckTarget verifies if the target URL is accessible
func CheckTarget(u *url.URL) error {
	c := &http.Client{
		Timeout: 5 * time.Second,
	}

	if !strings.HasPrefix(u.Scheme, "http") && !strings.HasPrefix(u.Scheme, "https") {
		u.Scheme = "https"
	}

	r, err := c.Get(u.String())
	if err != nil {
		return fmt.Errorf("target not accessible: %v", err)
	}
	defer r.Body.Close()

	return nil
}
