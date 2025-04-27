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

func (s *Server) loadProxyConfigs() error {
	proxies := gViper.GetStringMap("proxies")
	if len(proxies) == 0 {
		return nil
	}

	g, ctx := errgroup.WithContext(context.Background())

	type proxySetup struct {
		domain    string
		proxy     *httputil.ReverseProxy
		targetURL *url.URL
		err       error
	}
	results := make(chan proxySetup, len(proxies))

	wildcardCerts := make(map[string]bool)
	wildcardDomainMap := make(map[string][]string)

	for domain := range proxies {
		domain := domain
		g.Go(func() error {
			var proxyConfig ProxyConfig
			if err := gViper.UnmarshalKey("proxies:"+domain, &proxyConfig); err != nil {
				results <- proxySetup{domain: domain, err: fmt.Errorf("error parsing proxy config: %v", err)}
				return nil
			}

			targetURL, err := url.Parse(proxyConfig.Target)
			if err != nil {
				results <- proxySetup{domain: domain, err: fmt.Errorf("error parsing target URL: %v", err)}
				return nil
			}

			if err := s.checkTarget(targetURL); err != nil {
				results <- proxySetup{domain: domain, err: fmt.Errorf("target not accessible: %v", err)}
				return nil
			}

			proxy := s.createReverseProxy(targetURL, domain)

			var certDomain string
			if proxyConfig.UseWildcardCert {
				certDomain = getWildcardDomain(domain)
				if certDomain == "" {
					results <- proxySetup{domain: domain, err: fmt.Errorf("invalid domain for wildcard cert: %s", domain)}
					return nil
				}
				wildcardCerts[certDomain] = true
				s.mu.Lock()
				wildcardDomainMap[certDomain] = append(wildcardDomainMap[certDomain], domain)
				s.mu.Unlock()

				if cert, err := s.certManager.GetCertificate(&tls.ClientHelloInfo{ServerName: domain}); err == nil && cert != nil {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case results <- proxySetup{domain: domain, proxy: proxy, targetURL: targetURL}:
					}
					return nil
				}
			} else {
				certDomain = domain
				if err := s.certManager.ObtainCert(certDomain); err != nil {
					s.addFailedCert(domain, err)
					results <- proxySetup{domain: domain, err: fmt.Errorf("error obtaining certificate: %v", err)}
					return nil
				}

				cert, err := s.certManager.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
				if err != nil || cert == nil {
					results <- proxySetup{domain: domain, err: fmt.Errorf("certificate verification failed: %v", err)}
					return nil
				}

				select {
				case <-ctx.Done():
					return ctx.Err()
				case results <- proxySetup{domain: domain, proxy: proxy, targetURL: targetURL}:
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

	// Phase 1: Obtain all wildcard certificates first
	for wildcardDomain := range wildcardCerts {
		if err := s.certManager.ObtainCert(wildcardDomain); err != nil {
			log.Warn("Failed to obtain wildcard certificate",
				"domain", wildcardDomain,
				"err", err)
			s.addFailedCert(wildcardDomain, err)
			if domains, ok := wildcardDomainMap[wildcardDomain]; ok {
				for _, domain := range domains {
					log.Warn("Domain affected by wildcard certificate failure", "domain", domain)
				}
			}
			continue
		}
	}

	// Phase 2: Prepare new proxy map but don't install it yet
	newProxies := make(map[string]*httputil.ReverseProxy)
	var successCount, errorCount int

	// Track which domains are in the new configuration
	configuredDomains := make(map[string]bool)
	for domain := range proxies {
		configuredDomains[domain] = true
	}

	for result := range results {
		if result.err != nil {
			log.Warn("Failed to configure proxy", "domain", result.domain, "err", result.err)
			errorCount++
			// Keep the existing proxy for failed domains if they were previously configured
			if oldProxy, exists := s.proxies[result.domain]; exists && configuredDomains[result.domain] {
				newProxies[result.domain] = oldProxy
				log.Info("Keeping existing proxy configuration", "domain", result.domain)
			}
			continue
		}
		newProxies[result.domain] = result.proxy
		successCount++
		log.Info("Successfully configured proxy",
			"domain", result.domain,
			"target", result.targetURL.String())
	}

	// Find domains that were removed from configuration
	s.mu.RLock()
	var removedCount int
	for domain := range s.proxies {
		if !configuredDomains[domain] {
			removedCount++
			log.Info("Removing proxy configuration", "domain", domain)
		}
	}
	s.mu.RUnlock()

	if successCount > 0 || removedCount > 0 {
		s.mu.Lock()
		s.proxies = newProxies
		s.mu.Unlock()
		log.Info("Updated proxy configurations",
			"success", successCount,
			"errors", errorCount,
			"removed", removedCount,
			"total", len(newProxies))
	} else if errorCount > 0 {
		log.Warn("No proxy configurations were successfully loaded", "errors", errorCount)
	}

	return nil
}
