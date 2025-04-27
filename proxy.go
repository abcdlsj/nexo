package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"golang.org/x/sync/errgroup"
)

type ProxyConfig struct {
	Target          string `mapstructure:"target"`
	UseWildcardCert bool   `mapstructure:"use_wildcard_cert"`
}

func (s *Server) handleHTTPS() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		proxy, ok := s.proxies[r.Host]
		s.mu.RUnlock()

		if !ok {
			// Try wildcard domain
			parts := strings.SplitN(r.Host, ".", 2)
			if len(parts) == 2 {
				wildcardDomain := "*." + parts[1]
				s.mu.RLock()
				proxy, ok = s.proxies[wildcardDomain]
				s.mu.RUnlock()
			}
		}

		if !ok {
			http.Error(w, "Domain not configured", http.StatusNotFound)
			return
		}

		proxy.ServeHTTP(w, r)
	})
}

func (s *Server) createReverseProxy(targetURL *url.URL, domain string) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Forwarded-Proto", "https")
		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
			location := resp.Header.Get("Location")
			if location != "" {
				locationURL, err := url.Parse(location)
				if err != nil {
					return err
				}
				if locationURL.Host == targetURL.Host {
					locationURL.Host = domain
					locationURL.Scheme = "https"
					resp.Header.Set("Location", locationURL.String())
				}
			}
		}
		return nil
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Error("Proxy error", "domain", domain, "err", err)
		http.Error(w, "Proxy Error", http.StatusBadGateway)
	}

	return proxy
}

func (s *Server) checkTarget(targetURL *url.URL) error {
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

func (s *Server) loadProxies() error {
	proxies := gViper.GetStringMap("proxies")
	if len(proxies) == 0 {
		return nil
	}

	g, ctx := errgroup.WithContext(context.Background())

	type setup struct {
		domain string
		proxy  *httputil.ReverseProxy
		target *url.URL
		err    error
	}
	results := make(chan setup, len(proxies))

	wildcards := make(map[string]bool)
	wildcardDomains := make(map[string][]string)

	// Track which domains are in the new configuration
	domains := make(map[string]bool)
	for domain := range proxies {
		domains[domain] = true
	}

	for domain := range proxies {
		domain := domain
		g.Go(func() error {
			var cfg ProxyConfig
			if err := gViper.UnmarshalKey("proxies:"+domain, &cfg); err != nil {
				results <- setup{domain: domain, err: fmt.Errorf("error parsing proxy config: %v", err)}
				return nil
			}

			target, err := url.Parse(cfg.Target)
			if err != nil {
				results <- setup{domain: domain, err: fmt.Errorf("error parsing target URL: %v", err)}
				return nil
			}

			if err := s.checkTarget(target); err != nil {
				results <- setup{domain: domain, err: fmt.Errorf("target not accessible: %v", err)}
				return nil
			}

			proxy := s.createReverseProxy(target, domain)

			var certDomain string
			if cfg.UseWildcardCert {
				certDomain = getWildcardDomain(domain)
				if certDomain == "" {
					results <- setup{domain: domain, err: fmt.Errorf("invalid domain for wildcard cert: %s", domain)}
					return nil
				}
				wildcards[certDomain] = true
				s.mu.Lock()
				wildcardDomains[certDomain] = append(wildcardDomains[certDomain], domain)
				s.mu.Unlock()

				if cert, err := s.certManager.GetCertificate(&tls.ClientHelloInfo{ServerName: domain}); err == nil && cert != nil {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case results <- setup{domain: domain, proxy: proxy, target: target}:
					}
					return nil
				}
			} else {
				certDomain = domain
				if err := s.certManager.ObtainCert(certDomain); err != nil {
					s.addFailedCert(domain, err)
					results <- setup{domain: domain, err: fmt.Errorf("error obtaining certificate: %v", err)}
					return nil
				}

				cert, err := s.certManager.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
				if err != nil || cert == nil {
					results <- setup{domain: domain, err: fmt.Errorf("certificate verification failed: %v", err)}
					return nil
				}

				select {
				case <-ctx.Done():
					return ctx.Err()
				case results <- setup{domain: domain, proxy: proxy, target: target}:
				}
			}

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		close(results)
		return err
	}
	close(results)

	// Find domains that were removed from configuration
	s.mu.RLock()
	var removed int
	for domain := range s.proxies {
		if !domains[domain] {
			removed++
			log.Info("Removing proxy configuration", "domain", domain)
		}
	}
	s.mu.RUnlock()

	// Phase 1: Obtain all wildcard certificates first
	for domain := range wildcards {
		if err := s.certManager.ObtainCert(domain); err != nil {
			log.Warn("Failed to obtain wildcard certificate",
				"domain", domain,
				"err", err)
			s.addFailedCert(domain, err)
			if affected, ok := wildcardDomains[domain]; ok {
				for _, d := range affected {
					log.Warn("Domain affected by wildcard certificate failure", "domain", d)
				}
			}
			continue
		}
	}

	// Phase 2: Update proxy configurations
	newProxies := make(map[string]*httputil.ReverseProxy)
	var ok, fail int

	for result := range results {
		if result.err != nil {
			log.Warn("Failed to configure proxy", "domain", result.domain, "err", result.err)
			fail++
			// Keep the existing proxy for failed domains if they were previously configured
			if oldProxy, exists := s.proxies[result.domain]; exists && domains[result.domain] {
				newProxies[result.domain] = oldProxy
				log.Info("Keeping existing proxy configuration", "domain", result.domain)
			}
			continue
		}
		newProxies[result.domain] = result.proxy
		ok++
		log.Info("Successfully configured proxy",
			"domain", result.domain,
			"target", result.target.String())
	}

	if ok > 0 || removed > 0 {
		s.mu.Lock()
		s.proxies = newProxies
		s.mu.Unlock()
		log.Info("Updated proxy configurations",
			"ok", ok,
			"fail", fail,
			"removed", removed,
			"total", len(newProxies))
	} else if fail > 0 {
		log.Warn("No proxy configurations were successfully loaded", "errors", fail)
	}

	return nil
}
