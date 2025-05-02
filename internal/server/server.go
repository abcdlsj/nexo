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

const (
	// Server timeouts
	readTimeout       = 30 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 120 * time.Second
	readHeaderTimeout = 10 * time.Second

	// Certificate management
	certRetryInterval = 1 * time.Hour
	certRenewInterval = 24 * time.Hour
	certRetryDelay    = 24 * time.Hour

	// Request limits
	maxRequestSize    = 10 << 20 // 10MB
	maxHeaderSize     = 1 << 20  // 1MB
	keepAliveDuration = 3 * time.Minute
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
	if err := s.loadProxies(); err != nil {
		return fmt.Errorf("failed to load proxy configs: %v", err)
	}

	server := &http.Server{
		Addr:              ":443",
		Handler:           s.handleHTTPS(),
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		ReadHeaderTimeout: readHeaderTimeout,
		MaxHeaderBytes:    maxHeaderSize,
		TLSConfig:         s.createTLSConfig(),
	}

	ln, err := s.createListener()
	if err != nil {
		return err
	}

	return server.Serve(ln)
}

func (s *Server) createTLSConfig() *tls.Config {
	return &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{
				GetCertificate: s.certm.GetCertificate,
				MinVersion:     tls.VersionTLS12,
			}, nil
		},
	}
}

func (s *Server) createListener() (net.Listener, error) {
	ln, err := net.Listen("tcp", ":443")
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %v", err)
	}

	tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, s.createTLSConfig())
	return tlsListener, nil
}

// Stop stops the server
func (s *Server) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *Server) handleHTTPS() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

		host := s.extractHost(r)
		if host == "" {
			http.Error(w, "Invalid host", http.StatusBadRequest)
			return
		}

		handler := s.findHandler(host)
		if handler == nil {
			http.Error(w, "Domain not configured", http.StatusNotFound)
			return
		}

		handler.ServeHTTP(w, r)
	})
}

func (s *Server) extractHost(r *http.Request) string {
	host := strings.ToLower(r.Host)
	if !strings.Contains(host, ":") {
		return host
	}

	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return ""
	}
	return h
}

func (s *Server) findHandler(host string) *proxy.Handler {
	s.mu.RLock()
	handler, ok := s.proxies[host]
	s.mu.RUnlock()

	if !ok {
		parts := strings.SplitN(host, ".", 2)
		if len(parts) == 2 {
			wildcardDomain := "*." + parts[1]
			s.mu.RLock()
			handler, ok = s.proxies[wildcardDomain]
			s.mu.RUnlock()
		}
	}

	return handler
}

func (s *Server) loadProxies() error {
	newProxies := make(map[string]*proxy.Handler)

	for domain, cfg := range s.cfg.Proxies {
		if err := s.setupProxy(domain, cfg, newProxies); err != nil {
			return err
		}
	}

	s.mu.Lock()
	s.proxies = newProxies
	s.mu.Unlock()

	return nil
}

func (s *Server) setupProxy(domain string, cfg *proxy.Config, proxies map[string]*proxy.Handler) error {
	target, err := url.Parse(cfg.Target)
	if err != nil {
		return fmt.Errorf("error parsing target URL for %s: %v", domain, err)
	}

	if err := proxy.CheckTarget(target); err != nil {
		return fmt.Errorf("target not accessible for %s: %v", domain, err)
	}

	certDomain := s.getCertDomain(domain, cfg)
	if certDomain == "" {
		return fmt.Errorf("invalid domain for wildcard cert: %s", domain)
	}

	if err := s.ensureCertificate(domain, certDomain); err != nil {
		return err
	}

	proxies[domain] = proxy.New(target, domain)
	return nil
}

func (s *Server) getCertDomain(domain string, cfg *proxy.Config) string {
	if !cfg.UseWildcardCert {
		return domain
	}
	return getWildcardDomain(domain)
}

func (s *Server) ensureCertificate(domain, certDomain string) error {
	if _, err := s.certm.GetCertificate(&tls.ClientHelloInfo{ServerName: domain}); err != nil {
		log.Info("Certificate not found, obtaining new certificate", "domain", domain)
		if err := s.certm.ObtainCert(certDomain); err != nil {
			s.addFailedCert(domain, err)
			return fmt.Errorf("error obtaining certificate for %s: %v", domain, err)
		}
		log.Info("Successfully obtained certificate", "domain", domain)
	}
	return nil
}

func (s *Server) renewCerts() {
	ticker := time.NewTicker(certRenewInterval)
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
	ticker := time.NewTicker(certRetryInterval)
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
		if time.Since(lastTry) > certRetryDelay {
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
	tc.SetKeepAlivePeriod(keepAliveDuration)
	return tc, nil
}

func getWildcardDomain(domain string) string {
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) != 2 || !strings.HasPrefix(domain, "*.") {
		return ""
	}
	return domain
}
