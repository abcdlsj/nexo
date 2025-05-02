package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/abcdlsj/nexo/pkg/cert"
	"github.com/abcdlsj/nexo/pkg/config"
	"github.com/abcdlsj/nexo/pkg/proxy"
	"github.com/charmbracelet/log"
)

// Server represents the HTTPS proxy server
type Server struct {
	ctx    context.Context
	cancel context.CancelFunc

	cfg     *config.Config
	certm   *cert.Manager
	proxies map[string]*proxy.Handler

	failCerts   map[string]time.Time
	failCertsMu sync.RWMutex

	mu sync.RWMutex
}

// New creates a new server instance
func New(cfg *config.Config) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	certCfg := cert.Config{
		CertDir:    cfg.CertDir,
		Email:      cfg.Email,
		CFAPIToken: cfg.Cloudflare.APIToken,
	}

	s := &Server{
		ctx:       ctx,
		cancel:    cancel,
		cfg:       cfg,
		certm:     cert.New(certCfg),
		proxies:   make(map[string]*proxy.Handler),
		failCerts: make(map[string]time.Time),
	}

	// Start certificate renewal goroutine
	go s.renewCerts()

	// Start retry failed certificates goroutine
	go s.retryCerts()

	return s
}

// Start starts the HTTPS server
func (s *Server) Start() error {
	// Load proxy configurations
	if err := s.loadProxies(); err != nil {
		return fmt.Errorf("failed to load proxy configs: %v", err)
	}

	// Start HTTPS server
	server := &http.Server{
		Addr: ":443",
		TLSConfig: &tls.Config{
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				return &tls.Config{
					GetCertificate: s.certm.GetCertificate,
					MinVersion:     tls.VersionTLS12,
				}, nil
			},
		},
		Handler:           s.handleHTTPS(),
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// Enable TCP keep-alive
	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return err
	}

	tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, server.TLSConfig)
	return server.Serve(tlsListener)
}

// Stop stops the server
func (s *Server) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *Server) handleHTTPS() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Limit request body size to 10MB
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)

		host := strings.ToLower(r.Host)
		if strings.Contains(host, ":") {
			var err error
			host, _, err = net.SplitHostPort(host)
			if err != nil {
				http.Error(w, "Invalid host", http.StatusBadRequest)
				return
			}
		}

		s.mu.RLock()
		handler, ok := s.proxies[host]
		s.mu.RUnlock()

		if !ok {
			// Try wildcard domain
			parts := strings.SplitN(host, ".", 2)
			if len(parts) == 2 {
				wildcardDomain := "*." + parts[1]
				s.mu.RLock()
				handler, ok = s.proxies[wildcardDomain]
				s.mu.RUnlock()
			}
		}

		if !ok {
			http.Error(w, "Domain not configured", http.StatusNotFound)
			return
		}

		handler.ServeHTTP(w, r)
	})
}

func (s *Server) loadProxies() error {
	newProxies := make(map[string]*proxy.Handler)

	for domain, cfg := range s.cfg.Proxies {
		target, err := url.Parse(cfg.Target)
		if err != nil {
			return fmt.Errorf("error parsing target URL for %s: %v", domain, err)
		}

		if err := proxy.CheckTarget(target); err != nil {
			return fmt.Errorf("target not accessible for %s: %v", domain, err)
		}

		certDomain := domain
		if cfg.UseWildcardCert {
			certDomain = getWildcardDomain(domain)
			if certDomain == "" {
				return fmt.Errorf("invalid domain for wildcard cert: %s", domain)
			}
		}

		// Try to get existing certificate
		if _, err := s.certm.GetCertificate(&tls.ClientHelloInfo{ServerName: domain}); err != nil {
			log.Info("Certificate not found, obtaining new certificate", "domain", domain)
			if err := s.certm.ObtainCert(certDomain); err != nil {
				s.addFailedCert(domain, err)
				return fmt.Errorf("error obtaining certificate for %s: %v", domain, err)
			}
			log.Info("Successfully obtained certificate", "domain", domain)
		}

		newProxies[domain] = proxy.New(target, domain)
	}

	s.mu.Lock()
	s.proxies = newProxies
	s.mu.Unlock()

	return nil
}

func (s *Server) renewCerts() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.mu.RLock()
			domains := make([]string, 0, len(s.proxies))
			for domain := range s.proxies {
				domains = append(domains, domain)
			}
			s.mu.RUnlock()

			for _, domain := range domains {
				if err := s.certm.ObtainCert(domain); err != nil {
					log.Error("Failed to renew certificate", "domain", domain, "err", err)
				}
			}
		}
	}
}

func (s *Server) retryCerts() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.checkFailedCerts()
		}
	}
}

func (s *Server) addFailedCert(domain string, err error) {
	s.failCertsMu.Lock()
	s.failCerts[domain] = time.Now()
	s.failCertsMu.Unlock()
	log.Error("Failed to obtain certificate", "domain", domain, "err", err)
}

func (s *Server) checkFailedCerts() {
	s.failCertsMu.Lock()
	defer s.failCertsMu.Unlock()

	for domain, lastTry := range s.failCerts {
		if time.Since(lastTry) > 24*time.Hour {
			if err := s.certm.ObtainCert(domain); err != nil {
				s.failCerts[domain] = time.Now()
				log.Error("Failed to obtain certificate (retry)", "domain", domain, "err", err)
			} else {
				delete(s.failCerts, domain)
				log.Info("Successfully obtained certificate (retry)", "domain", domain)
			}
		}
	}
}

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

func getWildcardDomain(domain string) string {
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) != 2 || !strings.HasPrefix(domain, "*.") {
		return ""
	}
	return domain
}
