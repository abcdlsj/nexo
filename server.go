package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/sync/errgroup"
)

type Server struct {
	certManager *CertManager
	proxies     map[string]*httputil.ReverseProxy
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	// 记录证书获取失败的域名及其下次重试时间
	failedCerts   map[string]time.Time
	failedCertsMu sync.RWMutex
}

type ProxyConfig struct {
	Target          string `mapstructure:"target"`
	UseWildcardCert bool   `mapstructure:"use_wildcard_cert"`
}

func New() *Server {
	ctx, cancel := context.WithCancel(context.Background())

	// Get certificate directory from config
	certDir := gViper.GetString("cert_dir")
	if certDir == "" {
		baseDir := gViper.GetString("base_dir")
		if baseDir == "" {
			panic("base_dir not found in config")
		}
		certDir = filepath.Join(baseDir, "certs")
	}

	// Create CertManager configuration
	certConfig := Config{
		CertDir:    certDir,
		Email:      gViper.GetString("email"),
		CFAPIToken: gViper.GetString("cloudflare:api_token"),
	}

	s := &Server{
		certManager: NewCertManager(certConfig),
		proxies:     make(map[string]*httputil.ReverseProxy),
		ctx:         ctx,
		cancel:      cancel,
		failedCerts: make(map[string]time.Time),
	}

	// Start certificate renewal goroutine
	go s.autoRenewCertificates()

	// Start retry failed certificates goroutine
	go s.retryFailedCertificates()

	// Setup config file watcher
	gViper.OnConfigChange(func(e fsnotify.Event) {
		fmt.Printf("Config file changed: %s\n", e.Name)
		if err := s.reloadConfig(); err != nil {
			fmt.Printf("Error reloading config: %v\n", err)
		}
	})
	gViper.WatchConfig()

	return s
}

func (s *Server) reloadConfig() error {
	s.mu.Lock()
	// Clear existing proxies
	s.proxies = make(map[string]*httputil.ReverseProxy)
	s.mu.Unlock()

	// Reload proxy configurations
	return s.loadProxyConfigs()
}

func (s *Server) autoRenewCertificates() {
	ticker := time.NewTicker(24 * time.Hour) // Check daily
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.mu.RLock()
			// 收集所有需要的证书域名
			certDomains := make(map[string]bool)
			for domain := range s.proxies {
				// 获取域名的配置
				var proxyConfig ProxyConfig
				if err := gViper.UnmarshalKey("proxies:"+domain, &proxyConfig); err != nil {
					fmt.Printf("Error getting config for %s: %v\n", domain, err)
					continue
				}

				if proxyConfig.UseWildcardCert {
					if wildcardDomain := getWildcardDomain(domain); wildcardDomain != "" {
						certDomains[wildcardDomain] = true
					}
				} else {
					certDomains[domain] = true
				}
			}
			s.mu.RUnlock()

			// 更新所有需要的证书
			for domain := range certDomains {
				if err := s.certManager.ObtainCert(domain); err != nil {
					fmt.Printf("Error renewing certificate for %s: %v\n", domain, err)
				} else {
					fmt.Printf("Successfully renewed certificate for %s\n", domain)
				}
			}
		}
	}
}

func (s *Server) retryFailedCertificates() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			var domainsToRetry []string

			// 收集需要重试的域名
			s.failedCertsMu.RLock()
			for domain, retryTime := range s.failedCerts {
				if now.After(retryTime) {
					domainsToRetry = append(domainsToRetry, domain)
				}
			}
			s.failedCertsMu.RUnlock()

			// 重试这些域名
			for _, domain := range domainsToRetry {
				fmt.Printf("Retrying certificate acquisition for %s\n", domain)
				if err := s.certManager.ObtainCert(domain); err != nil {
					fmt.Printf("Retry failed for %s: %v\n", domain, err)
					s.addFailedCert(domain, err)
				} else {
					fmt.Printf("Successfully obtained certificate for %s\n", domain)
					// 成功后从失败列表中移除
					s.failedCertsMu.Lock()
					delete(s.failedCerts, domain)
					s.failedCertsMu.Unlock()

					// 检查是否是通配符证书
					if strings.HasPrefix(domain, "*.") {
						fmt.Printf("Successfully obtained wildcard certificate for %s, reloading all proxy configurations\n", domain)
						// 通配符证书获取成功，重新加载所有配置
						if err := s.reloadConfig(); err != nil {
							fmt.Printf("Error reloading config after successful wildcard cert retry: %v\n", err)
						}
					} else {
						// 单个域名证书，只需要重新加载该域名的配置
						var proxyConfig ProxyConfig
						if err := gViper.UnmarshalKey("proxies:"+domain, &proxyConfig); err != nil {
							fmt.Printf("Error loading proxy config for %s after cert retry: %v\n", domain, err)
							continue
						}

						targetURL, err := url.Parse(proxyConfig.Target)
						if err != nil {
							fmt.Printf("Error parsing target URL for %s after cert retry: %v\n", domain, err)
							continue
						}

						s.mu.Lock()
						s.proxies[domain] = s.createReverseProxy(targetURL, domain)
						s.mu.Unlock()
						fmt.Printf("Successfully reconfigured proxy for %s\n", domain)
					}
				}
			}
		}
	}
}

func (s *Server) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *Server) Start() error {
	// Load proxy configurations
	if err := s.loadProxyConfigs(); err != nil {
		return fmt.Errorf("failed to load proxy configs: %v", err)
	}

	// Start HTTPS server
	server := &http.Server{
		Addr:    ":443",
		Handler: s.handleHTTPS(),
		TLSConfig: &tls.Config{
			GetCertificate: s.certManager.GetCertificate,
		},
	}

	return server.ListenAndServeTLS("", "")
}

func (s *Server) checkTarget(targetURL *url.URL) error {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// 确保有scheme
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

func (s *Server) createReverseProxy(targetURL *url.URL, domain string) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// 保存原始的 director 函数
	originalDirector := proxy.Director

	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// 设置 X-Forwarded-* 头
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Forwarded-Proto", "https")

		// 确保传递原始请求头
		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
	}

	// 修改响应，处理重定向
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
			location := resp.Header.Get("Location")
			if location != "" {
				locationURL, err := url.Parse(location)
				if err != nil {
					return err
				}

				// 如果是重定向到目标服务的域名，替换为我们的域名
				if locationURL.Host == targetURL.Host {
					locationURL.Host = domain
					locationURL.Scheme = "https"
					resp.Header.Set("Location", locationURL.String())
				}
			}
		}
		return nil
	}

	// 错误处理
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		fmt.Printf("Proxy error for %s: %v\n", domain, err)
		http.Error(w, "Proxy Error", http.StatusBadGateway)
	}

	return proxy
}

// 解析错误消息中的重试时间
func parseRetryTime(err error) (time.Time, bool) {
	errStr := err.Error()
	if strings.Contains(errStr, "retry after") {
		// 尝试提取重试时间
		parts := strings.Split(errStr, "retry after")
		if len(parts) > 1 {
			timeStr := strings.Split(parts[1], "UTC")[0]
			retryTime, err := time.Parse("2006-01-02 15:04:05", strings.TrimSpace(timeStr))
			if err == nil {
				return retryTime, true
			}
		}
	}
	// 如果无法解析时间，默认1小时后重试
	return time.Now().Add(1 * time.Hour), false
}

func (s *Server) addFailedCert(domain string, err error) {
	retryTime, _ := parseRetryTime(err)
	s.failedCertsMu.Lock()
	s.failedCerts[domain] = retryTime
	s.failedCertsMu.Unlock()
	fmt.Printf("Added %s to retry queue, will retry after %v\n", domain, retryTime.Format("2006-01-02 15:04:05 UTC"))
}

func (s *Server) loadProxyConfigs() error {
	proxies := gViper.GetStringMap("proxies")
	if len(proxies) == 0 {
		return nil
	}

	// Create error group with context
	g, ctx := errgroup.WithContext(context.Background())

	// Channel to collect results
	type proxySetup struct {
		domain    string
		proxy     *httputil.ReverseProxy
		targetURL *url.URL
		err       error
	}
	results := make(chan proxySetup, len(proxies))

	// Track wildcard certificates that need to be obtained
	wildcardCerts := make(map[string]bool)
	// Track domains that use each wildcard cert
	wildcardDomainMap := make(map[string][]string) // wildcardDomain -> []subdomains

	// Process each domain in parallel
	for domain := range proxies {
		domain := domain // Create new variable for goroutine
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

			// Check target accessibility
			if err := s.checkTarget(targetURL); err != nil {
				results <- proxySetup{domain: domain, err: fmt.Errorf("target not accessible: %v", err)}
				return nil
			}

			// Create reverse proxy
			proxy := s.createReverseProxy(targetURL, domain)

			// Handle certificate acquisition
			var certDomain string
			if proxyConfig.UseWildcardCert {
				certDomain = getWildcardDomain(domain)
				if certDomain == "" {
					results <- proxySetup{domain: domain, err: fmt.Errorf("invalid domain for wildcard cert: %s", domain)}
					return nil
				}
				wildcardCerts[certDomain] = true
				// Add to wildcard domain map
				s.mu.Lock()
				wildcardDomainMap[certDomain] = append(wildcardDomainMap[certDomain], domain)
				s.mu.Unlock()
			} else {
				certDomain = domain
				// Request certificate for non-wildcard domain immediately
				if err := s.certManager.ObtainCert(certDomain); err != nil {
					s.addFailedCert(domain, err)
					results <- proxySetup{domain: domain, err: fmt.Errorf("error obtaining certificate: %v", err)}
					return nil
				}
			}

			// Verify certificate
			cert, err := s.certManager.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
			if err != nil || cert == nil {
				results <- proxySetup{domain: domain, err: fmt.Errorf("certificate verification failed: %v", err)}
				return nil
			}

			// Send successful result through channel
			select {
			case <-ctx.Done():
				return ctx.Err()
			case results <- proxySetup{domain: domain, proxy: proxy, targetURL: targetURL}:
			}

			return nil
		})
	}

	// Wait for all goroutines to complete
	if err := g.Wait(); err != nil {
		close(results)
		return err
	}
	close(results)

	// Obtain wildcard certificates
	for wildcardDomain := range wildcardCerts {
		if err := s.certManager.ObtainCert(wildcardDomain); err != nil {
			fmt.Printf("Warning: Failed to obtain wildcard certificate for %s: %v\n", wildcardDomain, err)
			// Add to retry queue
			s.addFailedCert(wildcardDomain, err)
			// Mark all domains using this wildcard cert as failed
			if domains, ok := wildcardDomainMap[wildcardDomain]; ok {
				for _, domain := range domains {
					fmt.Printf("Warning: Domain %s affected by wildcard certificate failure\n", domain)
				}
			}
			continue
		}
	}

	// Collect results
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

// getWildcardDomain returns the wildcard domain for a given domain
// e.g., "api.example.com" -> "*.example.com"
func getWildcardDomain(domain string) string {
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) != 2 {
		return ""
	}
	return "*." + parts[1]
}
