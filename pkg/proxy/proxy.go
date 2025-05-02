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
	Target          string
	UseWildcardCert bool
}

// Handler represents a proxy handler
type Handler struct {
	proxy *httputil.ReverseProxy
	host  string
}

// New creates a new proxy handler
func New(target *url.URL, host string) *Handler {
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Director = createDirector(proxy.Director)
	proxy.ModifyResponse = createResponseModifier(target, host)
	proxy.ErrorHandler = createErrorHandler(host)

	return &Handler{
		proxy: proxy,
		host:  host,
	}
}

// ServeHTTP implements the http.Handler interface
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.proxy.ServeHTTP(w, r)
}

func createDirector(original func(*http.Request)) func(*http.Request) {
	return func(req *http.Request) {
		original(req)
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Forwarded-Proto", "https")
		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
	}
}

func createResponseModifier(target *url.URL, domain string) func(*http.Response) error {
	return func(resp *http.Response) error {
		if err := handleRedirect(resp, target, domain); err != nil {
			return err
		}
		setCacheHeaders(resp)
		return nil
	}
}

func handleRedirect(resp *http.Response, target *url.URL, domain string) error {
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		return nil
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return nil
	}

	locationURL, err := url.Parse(location)
	if err != nil {
		return err
	}

	if locationURL.Host == target.Host {
		locationURL.Host = domain
		locationURL.Scheme = "https"
		resp.Header.Set("Location", locationURL.String())
	}

	return nil
}

func createErrorHandler(host string) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		log.Error("Proxy error", "domain", host, "err", err)
		http.Error(w, "Proxy Error", http.StatusBadGateway)
	}
}

func setCacheHeaders(resp *http.Response) {
	contentType := resp.Header.Get("Content-Type")
	path := resp.Request.URL.Path
	ext := strings.ToLower(filepath.Ext(path))

	switch {
	case isStaticContent(contentType, ext):
		resp.Header.Set("Cache-Control", longTermCache)
	case isDynamicContent(contentType):
		resp.Header.Set("Cache-Control", noCache)
		resp.Header.Set("Pragma", "no-cache")
		resp.Header.Set("Expires", "0")
	default:
		resp.Header.Set("Cache-Control", shortTermCache)
	}
	resp.Header.Set("Vary", "Accept-Encoding")
}

func isStaticContent(contentType, ext string) bool {
	// Check content type prefixes
	for _, prefix := range strings.Split(staticPrefixes, ",") {
		if strings.HasPrefix(contentType, prefix) {
			return true
		}
	}

	// Check file extensions
	return strings.Contains(staticExtensions, ext)
}

func isDynamicContent(contentType string) bool {
	return strings.HasPrefix(contentType, "text/html") ||
		strings.HasPrefix(contentType, "application/json")
}

// CheckTarget verifies if the target URL is accessible
func CheckTarget(targetURL *url.URL) error {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	if !strings.HasPrefix(targetURL.Scheme, "http") {
		targetURL.Scheme = "http"
	}

	resp, err := client.Get(targetURL.String())
	if err != nil {
		return fmt.Errorf("target not accessible: %v", err)
	}
	defer resp.Body.Close()

	return nil
}
