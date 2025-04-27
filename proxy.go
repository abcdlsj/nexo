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
		fmt.Printf("Proxy error for %s: %v\n", domain, err)
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

	for wildcardDomain := range wildcardCerts {
		if err := s.certManager.ObtainCert(wildcardDomain); err != nil {
			fmt.Printf("Warning: Failed to obtain wildcard certificate for %s: %v\n", wildcardDomain, err)
			s.addFailedCert(wildcardDomain, err)
			if domains, ok := wildcardDomainMap[wildcardDomain]; ok {
				for _, domain := range domains {
					fmt.Printf("Warning: Domain %s affected by wildcard certificate failure\n", domain)
				}
			}
			continue
		}
	}

	s.mu.Lock()
	for result := range results {
		if result.err != nil {
			fmt.Printf("Warning: Failed to configure proxy for %s: %v\n", result.domain, result.err)
			continue
		}
		s.proxies[result.domain] = result.proxy
		fmt.Printf("Successfully configured proxy for %s -> %s\n", result.domain, result.targetURL.String())
	}
	s.mu.Unlock()

	return nil
}
