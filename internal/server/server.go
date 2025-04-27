package server

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"
)

type Server struct {
	certManager *CertManager
	proxies     map[string]*httputil.ReverseProxy
	mu          sync.RWMutex
}

type ProxyConfig struct {
	Target string `mapstructure:"target"`
}

func New() *Server {
	return &Server{
		certManager: NewCertManager(),
		proxies:     make(map[string]*httputil.ReverseProxy),
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

func (s *Server) loadProxyConfigs() error {
	proxies := viper.GetStringMap("proxies")
	for domain := range proxies {
		var proxyConfig ProxyConfig
		if err := viper.UnmarshalKey("proxies."+domain, &proxyConfig); err != nil {
			return fmt.Errorf("error parsing proxy config for domain %s: %v", domain, err)
		}

		targetURL, err := url.Parse(proxyConfig.Target)
		if err != nil {
			return fmt.Errorf("error parsing target URL for domain %s: %v", domain, err)
		}

		// 检查目标地址是否可访问
		if err := s.checkTarget(targetURL); err != nil {
			return fmt.Errorf("domain %s: %v", domain, err)
		}

		s.mu.Lock()
		s.proxies[domain] = s.createReverseProxy(targetURL, domain)
		s.mu.Unlock()

		// Request certificate for the domain
		if err := s.certManager.ObtainCert(domain); err != nil {
			return fmt.Errorf("error obtaining certificate for domain %s: %v", domain, err)
		}

		// 验证证书是否正确加载
		cert, err := s.certManager.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
		if err != nil {
			return fmt.Errorf("certificate verification failed for domain %s: %v", domain, err)
		}
		if cert == nil {
			return fmt.Errorf("certificate not loaded for domain %s", domain)
		}

		fmt.Printf("Successfully configured proxy for %s -> %s\n", domain, targetURL.String())
	}

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
