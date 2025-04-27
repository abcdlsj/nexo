package server

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"

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
	s.loadProxyConfigs()

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

func (s *Server) loadProxyConfigs() {
	proxies := viper.GetStringMap("proxies")
	for domain, _ := range proxies {
		var proxyConfig ProxyConfig
		if err := viper.UnmarshalKey("proxies."+domain, &proxyConfig); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing proxy config for domain %s: %v\n", domain, err)
			continue
		}

		targetURL, err := url.Parse(proxyConfig.Target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing target URL for domain %s: %v\n", domain, err)
			continue
		}

		s.mu.Lock()
		s.proxies[domain] = httputil.NewSingleHostReverseProxy(targetURL)
		s.mu.Unlock()

		// Request certificate for the domain
		if err := s.certManager.ObtainCert(domain); err != nil {
			fmt.Fprintf(os.Stderr, "Error obtaining certificate for domain %s: %v\n", domain, err)
		}
	}
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
