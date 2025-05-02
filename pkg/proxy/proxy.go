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

	// Configure director
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Forwarded-Proto", "https")
		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
	}

	// Configure response modifier
	proxy.ModifyResponse = createResponseModifier(target, host)

	// Configure error handler
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

func createResponseModifier(target *url.URL, domain string) func(*http.Response) error {
	return func(resp *http.Response) error {
		if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
			location := resp.Header.Get("Location")
			if location != "" {
				locationURL, err := url.Parse(location)
				if err != nil {
					return err
				}
				if locationURL.Host == target.Host {
					locationURL.Host = domain
					locationURL.Scheme = "https"
					resp.Header.Set("Location", locationURL.String())
				}
			}
		}

		setCacheHeaders(resp)
		return nil
	}
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
	case strings.HasPrefix(contentType, "image/"),
		strings.HasPrefix(contentType, "video/"),
		strings.HasPrefix(contentType, "audio/"),
		ext == ".css",
		ext == ".js",
		ext == ".woff",
		ext == ".woff2",
		ext == ".ttf",
		ext == ".eot":
		resp.Header.Set("Cache-Control", "public, max-age=604800, stale-while-revalidate=86400")
		resp.Header.Set("Vary", "Accept-Encoding")
	case strings.HasPrefix(contentType, "text/html"),
		strings.HasPrefix(contentType, "application/json"):
		resp.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
		resp.Header.Set("Pragma", "no-cache")
		resp.Header.Set("Expires", "0")
	default:
		resp.Header.Set("Cache-Control", "public, max-age=3600, stale-while-revalidate=600")
		resp.Header.Set("Vary", "Accept-Encoding")
	}
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
