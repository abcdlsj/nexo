package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
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
	staticPrefixes = "image/,video/,audio/"
)

var staticExtensions = map[string]struct{}{
	".css": {}, ".js": {}, ".woff": {}, ".woff2": {}, ".ttf": {}, ".eot": {},
}

// Config represents the configuration for a proxy
type Config struct {
	Upstream string `mapstructure:"upstream" yaml:"upstream,omitempty"`
	Redirect string `mapstructure:"redirect" yaml:"redirect,omitempty"`
	Auth     bool   `mapstructure:"auth" yaml:"auth,omitempty"` // Enable OAuth authentication for this proxy

	// WriteTimeout optionally caps the total time allowed to write a response
	// for this route. Accepts Go duration strings (e.g. "5m"); empty or "0"
	// disables the cap so long-lived streams (SSE/WebSocket) are not cut.
	WriteTimeout string `mapstructure:"write_timeout" yaml:"write_timeout,omitempty"`

	// ResponseHeaderTimeout caps how long the proxy waits for upstream response
	// headers. Accepts Go duration strings; "0" waits indefinitely.
	ResponseHeaderTimeout string `mapstructure:"response_header_timeout" yaml:"response_header_timeout,omitempty"`

	// Retry enables one retry when an upstream connection fails before any
	// response byte is sent. For safety it only applies to idempotent methods
	// (GET/HEAD/OPTIONS) and never when the client already canceled.
	Retry bool `mapstructure:"retry" yaml:"retry,omitempty"`
}

// Handler represents a proxy handler
type Handler struct {
	proxy                 *httputil.ReverseProxy
	redirect              string
	upstream              string
	host                  string
	writeTimeoutRaw       string
	responseHeaderTimeout string
	retryEnabled          bool
}

// ConfigChanged checks if the configuration has changed
func (h *Handler) ConfigChanged(newCfg *Config) bool {
	if h.redirect != "" {
		return h.redirect != newCfg.Redirect
	}
	return h.upstream != newCfg.Upstream ||
		h.writeTimeoutRaw != newCfg.WriteTimeout ||
		h.responseHeaderTimeout != newCfg.ResponseHeaderTimeout ||
		h.retryEnabled != newCfg.Retry
}

// WriteDeadline returns the per-route total write deadline and whether the
// route explicitly configured one. When a route leaves write_timeout unset,
// the server-level setting (if any) applies.
func (h *Handler) WriteDeadline() (time.Duration, bool) {
	if h == nil || h.writeTimeoutRaw == "" {
		return 0, false
	}
	return ParseDuration(h.writeTimeoutRaw, 0), true
}

// ParseDuration parses a Go duration string. Empty values produce the fallback
// (zero means "no deadline"/"wait indefinitely"). Invalid values log a warning
// and fall back instead of failing the whole proxy.
func ParseDuration(raw string, fallback time.Duration) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		log.Warn("Invalid duration setting; using fallback", "value", raw, "fallback", fallback, "err", err)
		return fallback
	}
	return d
}

// newProxyTransport creates a Transport dedicated to upstream connections.
// Each proxy gets its own pool to isolate failures between upstreams.
func newProxyTransport(responseHeaderTimeout time.Duration) *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: responseHeaderTimeout,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
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
	defaultResponseHeaderTimeout := 30 * time.Second
	p.Transport = newProxyTransport(ParseDuration(cfg.ResponseHeaderTimeout, defaultResponseHeaderTimeout))
	p.FlushInterval = -1 // flush immediately for streaming responses
	p.Director = createDirector(p.Director)
	p.ModifyResponse = createResponseModifier(target, host)
	p.ErrorHandler = createErrorHandler(host, p, cfg.Retry)

	return &Handler{
		proxy:                 p,
		upstream:              cfg.Upstream,
		host:                  host,
		writeTimeoutRaw:       cfg.WriteTimeout,
		responseHeaderTimeout: cfg.ResponseHeaderTimeout,
		retryEnabled:          cfg.Retry,
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

type retryKey struct{}

func createErrorHandler(host string, proxy *httputil.ReverseProxy, retry bool) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		if retry && !retryAttempted(r) && shouldRetryUpstream(r, err) {
			r = r.WithContext(context.WithValue(r.Context(), retryKey{}, true))
			time.Sleep(100 * time.Millisecond)
			proxy.ServeHTTP(w, r)
			return
		}
		log.Error("Proxy error", "domain", host, "err", err)
		http.Error(w, "Proxy Error", http.StatusBadGateway)
	}
}

func retryAttempted(r *http.Request) bool {
	return r != nil && r.Context().Value(retryKey{}) != nil
}

// shouldRetryUpstream limits retries to idempotent methods and excludes
// client-side cancellation, which retrying cannot fix.
func shouldRetryUpstream(r *http.Request, err error) bool {
	if err == nil || r == nil || r.Method == "" {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if r.Context().Err() != nil {
		return false
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func setCacheHeaders(r *http.Response) {
	// Preserve intentional upstream policy. In particular, never turn private
	// or authenticated responses into shared-cacheable content.
	if r.Header.Get("Cache-Control") != "" {
		return
	}
	if r.Request.Header.Get("Authorization") != "" || r.Header.Get("Set-Cookie") != "" {
		r.Header.Set("Cache-Control", noCache)
		return
	}
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
		_, ok := staticExtensions[ext]
		return ok
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

// CheckTarget validates a target without making a network request. Eager GETs
// made startup and every config reload block for up to five seconds per route,
// and could trigger side effects on upstream applications.
func CheckTarget(u *url.URL) error {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("target must be an absolute HTTP(S) URL")
	}
	if u.User != nil {
		return fmt.Errorf("target URL must not contain credentials")
	}
	return nil
}
