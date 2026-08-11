package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/abcdlsj/nexo/pkg/proxy"
	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"
)

const (
	routeDiscoveryTTL         = 30 * time.Minute
	routeDiscoveryFailureTTL  = 2 * time.Minute
	routeDiscoveryTimeout     = 4 * time.Second
	routeDiscoveryMaxBodySize = 256 << 10
	routeIconMaxBodySize      = 512 << 10
)

var apiProbePaths = []string{"/openapi.json", "/swagger.json", "/api-docs", "/docs", "/health", "/healthz"}

type routeDiscoveryResult struct {
	Kind            string
	Icon            []byte
	IconContentType string
	Unavailable     bool
}

type routeDiscoveryCacheEntry struct {
	upstream string
	result   routeDiscoveryResult
	expires  time.Time
}

// routeDiscoverer only visits an explicitly configured upstream. Icon URLs
// discovered in HTML must remain on that same origin, so this cannot become a
// general-purpose fetch endpoint.
type routeDiscoverer struct {
	client *http.Client
	now    func() time.Time

	mu    sync.RWMutex
	cache map[string]routeDiscoveryCacheEntry
}

func newRouteDiscoverer() *routeDiscoverer {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   2 * time.Second,
		ResponseHeaderTimeout: 2 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   4,
	}
	return &routeDiscoverer{
		client: &http.Client{
			Transport: transport,
			Timeout:   3 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 || len(via) == 0 || !sameOrigin(req.URL, via[0].URL) {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		now:   time.Now,
		cache: make(map[string]routeDiscoveryCacheEntry),
	}
}

func (d *routeDiscoverer) discover(ctx context.Context, domain string, cfg *proxy.Config) routeDiscoveryResult {
	if d == nil || cfg == nil || cfg.Upstream == "" {
		return routeDiscoveryResult{Kind: "SERVICE"}
	}

	d.mu.RLock()
	entry, ok := d.cache[domain]
	d.mu.RUnlock()
	if ok && entry.upstream == cfg.Upstream && d.now().Before(entry.expires) {
		return entry.result
	}

	result := d.probe(ctx, domain, cfg.Upstream)
	ttl := routeDiscoveryTTL
	if result.Kind == "SERVICE" && len(result.Icon) == 0 {
		ttl = routeDiscoveryFailureTTL
	}
	d.mu.Lock()
	d.cache[domain] = routeDiscoveryCacheEntry{
		upstream: cfg.Upstream,
		result:   result,
		expires:  d.now().Add(ttl),
	}
	d.mu.Unlock()
	return result
}

func (h *Handler) discoverRoutes(parent context.Context) map[string]routeDiscoveryResult {
	if h == nil || h.routeDiscovery == nil {
		return nil
	}
	cfgSnapshot := h.config()
	ctx, cancel := context.WithTimeout(parent, routeDiscoveryTimeout)
	defer cancel()

	results := make(map[string]routeDiscoveryResult, len(cfgSnapshot.Proxies))
	var mu sync.Mutex
	var wait sync.WaitGroup
	semaphore := make(chan struct{}, 8)
	for domain, cfg := range cfgSnapshot.Proxies {
		if cfg == nil || cfg.Upstream == "" || (cfg.Portal != nil && cfg.Portal.Hidden) {
			continue
		}
		wait.Add(1)
		go func(domain string, cfg *proxy.Config) {
			defer wait.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				return
			}
			result := h.routeDiscovery.discover(ctx, domain, cfg)
			mu.Lock()
			results[domain] = result
			mu.Unlock()
		}(domain, cfg)
	}
	wait.Wait()
	return results
}

func (h *Handler) handleRouteIcon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if h == nil {
		http.NotFound(w, r)
		return
	}
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	cfg, ok := h.config().Proxies[domain]
	if !ok || cfg == nil || cfg.Upstream == "" || (cfg.Portal != nil && cfg.Portal.Hidden) {
		http.NotFound(w, r)
		return
	}

	result := routeDiscoveryResult{}
	if h.routeDiscovery != nil {
		result = h.routeDiscovery.discover(r.Context(), domain, cfg)
	}
	body := result.Icon
	contentType := result.IconContentType
	if len(body) == 0 || contentType == "" {
		w.Header().Set("Cache-Control", "private, max-age=120")
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "private, max-age=1800")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func (d *routeDiscoverer) probe(parent context.Context, domain, upstream string) routeDiscoveryResult {
	result := routeDiscoveryResult{Kind: "SERVICE"}
	base, err := url.Parse(strings.TrimSpace(upstream))
	if err != nil || base.User != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return result
	}
	if base.Path == "" {
		base.Path = "/"
	}

	ctx, cancel := context.WithTimeout(parent, routeDiscoveryTimeout)
	defer cancel()

	response, body, err := d.fetch(ctx, domain, base)
	if err != nil {
		result.Unavailable = true
	} else {
		result.Unavailable = response.StatusCode >= http.StatusInternalServerError
		result.Kind = classifyRouteResponse(response, body)
		if isHTMLResponse(response, body) {
			for _, candidate := range iconLinks(response.Request.URL, body) {
				if !sameOrigin(candidate, base) {
					continue
				}
				if icon, contentType := d.fetchIcon(ctx, domain, candidate); len(icon) > 0 {
					result.Icon = icon
					result.IconContentType = contentType
					break
				}
			}
		}
	}

	if len(result.Icon) == 0 {
		for _, path := range []string{"/favicon.ico", "/favicon.svg", "/apple-touch-icon.png"} {
			candidate := base.ResolveReference(&url.URL{Path: path})
			if icon, contentType := d.fetchIcon(ctx, domain, candidate); len(icon) > 0 {
				result.Icon = icon
				result.IconContentType = contentType
				break
			}
		}
	}

	if result.Kind == "SERVICE" {
		for _, path := range apiProbePaths {
			candidate := base.ResolveReference(&url.URL{Path: path})
			probeResponse, probeBody, probeErr := d.fetch(ctx, domain, candidate)
			if probeErr != nil {
				continue
			}
			kind := classifyRouteResponse(probeResponse, probeBody)
			if kind == "API" || (probeResponse.StatusCode >= 200 && probeResponse.StatusCode < 300 && path != "/docs" && path != "/health" && path != "/healthz") {
				result.Kind = "API"
				break
			}
		}
	}

	return result
}

func (d *routeDiscoverer) fetch(ctx context.Context, domain string, target *url.URL) (*http.Response, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	request.Host = domain
	request.Header.Set("Accept", "text/html, application/json;q=0.9, */*;q=0.5")
	request.Header.Set("User-Agent", "Nexo-Service-Discovery/1.0")
	response, err := d.client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, routeDiscoveryMaxBodySize+1))
	if err != nil {
		return nil, nil, err
	}
	if len(body) > routeDiscoveryMaxBodySize {
		body = body[:routeDiscoveryMaxBodySize]
	}
	return response, body, nil
}

func (d *routeDiscoverer) fetchIcon(ctx context.Context, domain string, target *url.URL) ([]byte, string) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, ""
	}
	request.Host = domain
	request.Header.Set("Accept", "image/avif,image/webp,image/svg+xml,image/*,*/*;q=0.5")
	request.Header.Set("User-Agent", "Nexo-Service-Discovery/1.0")
	response, err := d.client.Do(request)
	if err != nil {
		return nil, ""
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, ""
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, routeIconMaxBodySize+1))
	if err != nil || len(body) == 0 || len(body) > routeIconMaxBodySize {
		return nil, ""
	}
	contentType := imageContentType(response.Header.Get("Content-Type"), body)
	if contentType == "" {
		return nil, ""
	}
	return body, contentType
}

func classifyRouteResponse(response *http.Response, body []byte) string {
	contentType := mediaType(response.Header.Get("Content-Type"))
	lowerType := strings.ToLower(contentType)
	trimmed := bytes.TrimSpace(body)
	if lowerType == "application/json" || strings.HasSuffix(lowerType, "+json") || json.Valid(trimmed) {
		return "API"
	}
	if response.StatusCode >= 200 && response.StatusCode < 400 && isHTMLContent(contentType, trimmed) {
		return "WEBSITE"
	}
	return "SERVICE"
}

func isHTMLResponse(response *http.Response, body []byte) bool {
	return isHTMLContent(mediaType(response.Header.Get("Content-Type")), bytes.TrimSpace(body))
}

func isHTMLContent(contentType string, body []byte) bool {
	if strings.EqualFold(contentType, "text/html") || strings.EqualFold(contentType, "application/xhtml+xml") {
		return true
	}
	lower := bytes.ToLower(body)
	return bytes.HasPrefix(lower, []byte("<!doctype html")) || bytes.HasPrefix(lower, []byte("<html"))
}

func iconLinks(base *url.URL, body []byte) []*url.URL {
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	links := make([]*url.URL, 0, 4)
	for len(links) < 8 {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			break
		}
		if tokenType != html.StartTagToken && tokenType != html.SelfClosingTagToken {
			continue
		}
		token := tokenizer.Token()
		if !strings.EqualFold(token.Data, "link") {
			continue
		}
		var rel, href string
		for _, attribute := range token.Attr {
			switch strings.ToLower(attribute.Key) {
			case "rel":
				rel = attribute.Val
			case "href":
				href = attribute.Val
			}
		}
		if href == "" || !relContainsIcon(rel) {
			continue
		}
		parsed, err := url.Parse(strings.TrimSpace(href))
		if err != nil {
			continue
		}
		resolved := base.ResolveReference(parsed)
		if resolved.Scheme == "http" || resolved.Scheme == "https" {
			links = append(links, resolved)
		}
	}
	return links
}

func relContainsIcon(rel string) bool {
	for _, value := range strings.Fields(strings.ToLower(rel)) {
		if value == "icon" || value == "apple-touch-icon" || value == "apple-touch-icon-precomposed" || value == "mask-icon" {
			return true
		}
	}
	return false
}

func sameOrigin(a, b *url.URL) bool {
	return a != nil && b != nil && strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func mediaType(raw string) string {
	value, _, err := mime.ParseMediaType(raw)
	if err != nil {
		return strings.TrimSpace(strings.SplitN(raw, ";", 2)[0])
	}
	return value
}

func imageContentType(header string, body []byte) string {
	contentType := strings.ToLower(mediaType(header))
	if strings.HasPrefix(contentType, "image/") {
		return contentType
	}
	trimmed := bytes.TrimSpace(body)
	lower := bytes.ToLower(trimmed)
	if bytes.HasPrefix(lower, []byte("<svg")) || (bytes.HasPrefix(lower, []byte("<?xml")) && bytes.Contains(lower[:min(len(lower), 512)], []byte("<svg"))) {
		return "image/svg+xml"
	}
	detected := http.DetectContentType(body)
	if strings.HasPrefix(detected, "image/") {
		return mediaType(detected)
	}
	return ""
}

func normalizeRouteKind(kind string) string {
	switch strings.ToUpper(strings.TrimSpace(kind)) {
	case "API":
		return "API"
	case "WEBSITE", "WEB":
		return "WEBSITE"
	case "SERVICE", "PROXY":
		return "SERVICE"
	default:
		return ""
	}
}

func isApexDomain(domain string) bool {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	_, icann := publicsuffix.PublicSuffix(domain)
	if !icann {
		return false
	}
	registrable, err := publicsuffix.EffectiveTLDPlusOne(domain)
	return err == nil && domain == registrable
}
