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
	"github.com/fsnotify/fsnotify"
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

	// Certificate renewal threshold
	renewalThreshold = 30 * 24 * time.Hour
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

	// Configuration watcher
	watcher    *fsnotify.Watcher
	configPath string
}

// New creates a new server instance
func New(cfg *config.Config, configPath string) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	certCfg := cert.Config{
		CertDir:    cfg.CertDir,
		Email:      cfg.Email,
		CFAPIToken: cfg.Cloudflare.APIToken,
	}

	s := &Server{
		ctx:        ctx,
		cancel:     cancel,
		cfg:        cfg,
		certm:      cert.New(certCfg),
		proxies:    make(map[string]*proxy.Handler),
		failCerts:  make(map[string]time.Time),
		configPath: configPath,
	}

	// Start certificate renewal goroutine
	go s.renewCerts()

	// Start retry failed certificates goroutine
	go s.retryCerts()

	return s
}

// Start starts the HTTPS server
func (s *Server) Start() error {
	if err := s.loadProxies(false); err != nil {
		return fmt.Errorf("failed to load proxy configs: %v", err)
	}

	// Setup configuration file watcher
	if err := s.setupConfigWatcher(); err != nil {
		log.Error("Failed to setup config watcher", "err", err)
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

	// Start admin server for manual reload
	go s.startAdminServer()

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
	if s.watcher != nil {
		s.watcher.Close()
	}
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

func (s *Server) loadProxies(reload bool) error {
	newProxies := make(map[string]*proxy.Handler)

	for domain, cfg := range s.cfg.Proxies {
		if err := s.setupProxy(domain, cfg, newProxies); err != nil {
			if !reload {
				continue
			}
			return err
		}
	}

	s.mu.Lock()
	s.proxies = newProxies
	s.mu.Unlock()

	return nil
}

func (s *Server) setupProxy(domain string, cfg *proxy.Config, proxies map[string]*proxy.Handler) error {
	target, err := url.Parse(cfg.Upstream)
	if err != nil {
		return fmt.Errorf("error parsing upstream URL for %s: %v", domain, err)
	}

	if err := proxy.CheckTarget(target); err != nil {
		return fmt.Errorf("upstream not accessible for %s: %v", domain, err)
	}

	if err := s.handleCertObtain(domain, false); err != nil {
		return err
	}

	proxies[domain] = proxy.New(target, domain)
	return nil
}

func (s *Server) getCertDomain(domain string) string {
	// Extract the root domain
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ""
	}
	rootDomain := strings.Join(parts[len(parts)-2:], ".")

	// Check if the root domain is in the domains list
	for _, d := range s.cfg.Domains {
		if d == rootDomain {
			return "*." + rootDomain
		}
	}

	// If root domain is not in domains list, use the specific domain
	return domain
}

// handleCertObtain handles certificate obtaining with proper error handling and logging
func (s *Server) handleCertObtain(domain string, isRetry bool) error {
	certDomain := s.getCertDomain(domain)
	if certDomain == "" {
		log.Error("Invalid domain for certificate", "domain", domain, "operation", map[bool]string{true: "retry", false: "ensure"}[isRetry])
		return fmt.Errorf("invalid domain: %s", domain)
	}

	// First check if we already have a valid certificate
	cert, err := s.certm.GetCertificate(&tls.ClientHelloInfo{ServerName: certDomain})
	if err == nil && cert != nil && !needsRenewal(cert) {
		if isRetry {
			// If this is a retry and we have a valid cert, remove it from failed certs
			delete(s.failCerts, domain)
			log.Info("Found valid certificate during retry", "domain", certDomain)
		}
		return nil
	}

	// Need to obtain a new certificate
	if err := s.certm.ObtainCert(certDomain); err != nil {
		if isRetry {
			s.failCerts[domain] = time.Now()
			log.Error("Failed to obtain certificate (retry)", "domain", certDomain, "err", err)
		} else {
			s.addFailedCert(domain, err)
			log.Error("Failed to obtain certificate", "domain", certDomain, "err", err)
		}
		return err
	}

	if isRetry {
		delete(s.failCerts, domain)
		log.Info("Successfully obtained certificate (retry)", "domain", certDomain)
	} else {
		log.Info("Successfully obtained certificate", "domain", certDomain)
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
				s.handleCertObtain(domain, false)
			}
		}
	}
}

func needsRenewal(cert *tls.Certificate) bool {
	leaf := cert.Leaf
	if leaf == nil {
		return true
	}

	return time.Until(leaf.NotAfter) < renewalThreshold
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
	log.Error("Add to failed retry certs", "domain", domain, "err", err)
}

func (s *Server) checkFailedCerts() {
	s.failCertsMu.Lock()
	defer s.failCertsMu.Unlock()

	for domain, lastTry := range s.failCerts {
		if time.Since(lastTry) > certRetryDelay {
			s.handleCertObtain(domain, true)
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

// setupConfigWatcher sets up fsnotify watcher for configuration file changes
func (s *Server) setupConfigWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %v", err)
	}

	s.watcher = watcher

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					log.Info("Config file modified, reloading configuration")
					if err := s.Reload(); err != nil {
						log.Error("Failed to reload configuration", "err", err)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Error("Config watcher error", "err", err)
			case <-s.ctx.Done():
				return
			}
		}
	}()

	// Watch the config file
	if s.configPath != "" {
		return watcher.Add(s.configPath)
	}

	return nil
}

// Reload reloads the configuration and updates the proxies
func (s *Server) Reload() error {
	// Reload configuration file
	newCfg, err := config.Load(s.configPath)
	if err != nil {
		return fmt.Errorf("failed to reload config: %v", err)
	}

	s.cfg = newCfg
	return s.loadProxies(true)
}

// startAdminServer starts a simple HTTP server for administrative tasks
func (s *Server) startAdminServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := s.Reload(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Configuration reloaded successfully")
	})

	adminServer := &http.Server{
		Addr:    ":8080", // Admin port
		Handler: mux,
	}

	if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("Admin server error", "err", err)
	}
}
