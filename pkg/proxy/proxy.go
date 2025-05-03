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
	longTermCache  = "public, max-age=604800, stale-while-revalidate=86400" // 7 days
	shortTermCache = "public, max-age=3600, stale-while-revalidate=600"     // 1 hour
	noCache        = "no-cache, no-store, must-revalidate"

	// File extensions and content types that should use long-term caching
	staticExtensions = ".css,.js,.woff,.woff2,.ttf,.eot"
	staticPrefixes   = "image/,video/,audio/"
)

// Config represents the configuration for a proxy
type Config struct {
	Upstream string `mapstructure:"upstream"`
	Redirect string `mapstructure:"redirect"`
}

// Handler represents a proxy handler
type Handler struct {
	proxy    *httputil.ReverseProxy
	redirect string
	host     string
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
		proxy: p,
		host:  host,
	}
}

// ServeHTTP implements the http.Handler interface
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.redirect != "" {
		target := h.redirect
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
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
	p := r.Request.URL.Path
	ext := strings.ToLower(filepath.Ext(p))

	switch {
	case isStaticContent(ct, ext):
		r.Header.Set("Cache-Control", longTermCache)
	case isDynamicContent(ct):
		r.Header.Set("Cache-Control", noCache)
		r.Header.Set("Pragma", "no-cache")
		r.Header.Set("Expires", "0")
	default:
		r.Header.Set("Cache-Control", shortTermCache)
	}
	r.Header.Set("Vary", "Accept-Encoding")
}

func isStaticContent(ct, ext string) bool {
	for _, p := range strings.Split(staticPrefixes, ",") {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	return strings.Contains(staticExtensions, ext)
}

func isDynamicContent(ct string) bool {
	return strings.HasPrefix(ct, "text/html") ||
		strings.HasPrefix(ct, "application/json")
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
