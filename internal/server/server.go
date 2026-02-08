package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/abcdlsj/nexo/internal/webui"
	"github.com/abcdlsj/nexo/pkg/auth"
	"github.com/abcdlsj/nexo/pkg/cert"
	"github.com/abcdlsj/nexo/pkg/config"
	"github.com/abcdlsj/nexo/pkg/proxy"
	"github.com/abcdlsj/nexo/pkg/traffic"
	"github.com/charmbracelet/log"
	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
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

const domainNotConfiguredHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Domain Not Configured</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
        }
        .container {
            text-align: center;
            padding: 2rem;
            max-width: 600px;
        }
        .icon {
            font-size: 80px;
            margin-bottom: 1rem;
            opacity: 0.9;
        }
        h1 {
            font-size: 2.5rem;
            margin-bottom: 1rem;
            font-weight: 600;
        }
        p {
            font-size: 1.1rem;
            line-height: 1.6;
            margin-bottom: 1.5rem;
            opacity: 0.9;
        }
        .domain {
            background: rgba(255,255,255,0.2);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            font-family: monospace;
            font-size: 1rem;
            word-break: break-all;
        }
        .footer {
            margin-top: 3rem;
            font-size: 0.9rem;
            opacity: 0.7;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🔧</div>
        <h1>Domain Not Configured</h1>
        <p>The domain you are trying to access has not been configured on this server.</p>
        <p class="domain" id="domain"></p>
        <p>If you are the administrator, please check your configuration file.</p>
        <div class="footer">
            <p>Powered by <a href="https://github.com/abcdlsj/nexo" style="color: #fff; text-decoration: underline;">Nexo</a></p>
        </div>
    </div>
    <script>
        document.getElementById('domain').textContent = location.hostname;
    </script>
</body>
</html>`

type Server struct {
	ctx    context.Context
	cancel context.CancelFunc

	cfg        *config.Config
	certm      *cert.Manager
	authm      *auth.Manager
	proxies    map[string]*proxy.Handler
	trafficMgr *traffic.Manager

	failCerts   map[string]time.Time
	failCertsMu sync.RWMutex

	mu sync.RWMutex

	watcher *fsnotify.Watcher
	cfgPath string
}

func New(cfg *config.Config, cfgPath string) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	certCfg := cert.Config{
		CertDir:    cfg.CertDir,
		Email:      cfg.Email,
		CFAPIToken: cfg.Cloudflare.APIToken,
		Staging:    cfg.Staging,
	}

	m, err := cert.New(certCfg)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create certificate manager: %v", err)
	}

	// Initialize auth manager
	var authm *auth.Manager
	if cfg.Auth.GitHub.ClientID != "" {
		sessionTTL := 24 * time.Hour
		if cfg.Auth.SessionTTL != "" {
			if d, err := time.ParseDuration(cfg.Auth.SessionTTL); err == nil {
				sessionTTL = d
			}
		}

		// Ensure secret_key is set
		secretKey := cfg.Auth.SecretKey
		if secretKey == "" {
			secretKey = generateSecretKey()
			cfg.Auth.SecretKey = secretKey
			if err := saveConfig(cfg, cfgPath); err != nil {
				log.Warn("Failed to save generated secret_key", "err", err)
			} else {
				log.Info("Generated and saved secret_key to config")
			}
		}

		// Collect all proxy domains as allowed redirect hosts
		allowedHosts := make([]string, 0, len(cfg.Proxies))
		for domain := range cfg.Proxies {
			allowedHosts = append(allowedHosts, domain)
		}

		authm = auth.New(auth.Config{
			GitHub: auth.GitHubConfig{
				ClientID:     cfg.Auth.GitHub.ClientID,
				ClientSecret: cfg.Auth.GitHub.ClientSecret,
				AllowedUsers: cfg.Auth.GitHub.AllowedUsers,
			},
			AuthHost:     cfg.Auth.AuthHost,
			SecretKey:    secretKey,
			SessionTTL:   sessionTTL,
			AllowedHosts: allowedHosts,
		})

		if authm.Enabled() {
			log.Info("OAuth authentication enabled", "auth_host", cfg.Auth.AuthHost)
		}
	}

	// Initialize traffic manager
	trafficDir := filepath.Join(cfg.BaseDir, "traffic")
	trafficMgr := traffic.NewManager(trafficDir)

	s := &Server{
		ctx:        ctx,
		cancel:     cancel,
		cfg:        cfg,
		certm:      m,
		authm:      authm,
		proxies:    make(map[string]*proxy.Handler),
		trafficMgr: trafficMgr,
		failCerts:  make(map[string]time.Time),
		cfgPath:    cfgPath,
	}

	go s.renewCerts()
	go s.retryCerts()

	return s, nil
}

// Start starts the HTTPS server and WebUI
func (s *Server) Start() error {
	if err := s.setupConfigWatcher(); err != nil {
		log.Error("Failed to setup config watcher", "err", err)
	}

	// Start WebUI server first (in background)
	go s.startWebUI()

	// Wait for WebUI to be ready
	time.Sleep(3 * time.Second)

	// Then load proxies (so WebUI upstream is accessible)
	if err := s.loadProxies(false); err != nil {
		return fmt.Errorf("failed to load proxy configs: %v", err)
	}

	srv := &http.Server{
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

	return srv.Serve(ln)
}

// startWebUI starts the WebUI server
func (s *Server) startWebUI() {
	webuiHandler := webui.New(s.cfg, s.cfgPath, s.certm, s.authm, s.proxies, func() error {
		return s.Reload()
	}, s.trafficMgr)
	mux := http.NewServeMux()
	webuiHandler.RegisterRoutes(mux)

	webuiPort := ":8080"
	if s.cfg.WebUI.Port != "" {
		webuiPort = ":" + s.cfg.WebUI.Port
	}

	log.Info("Starting WebUI", "addr", webuiPort)

	srv := &http.Server{
		Addr:              webuiPort,
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Error("WebUI server error", "err", err)
	}
}

func (s *Server) createTLSConfig() *tls.Config {
	getCert := func(domain string) (*tls.Certificate, error) {
		// Try exact domain first
		cert, err := s.certm.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
		if err == nil {
			return cert, nil
		}

		// Try wildcard domain if available
		if wild, ok := s.cfg.GetWildcardDomain(domain); ok {
			cert, err := s.certm.GetCertificate(&tls.ClientHelloInfo{ServerName: wild})
			if err == nil {
				return cert, nil
			}
		}

		// In dev mode, generate self-signed certificate
		if s.cfg.Cloudflare.APIToken == "" {
			log.Warn("Using self-signed certificate for domain", "domain", domain)
			return s.generateSelfSignedCert(domain)
		}

		return nil, fmt.Errorf("no certificate found for domain: %s", domain)
	}

	return &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					return getCert(hello.ServerName)
				},
				MinVersion: tls.VersionTLS12,
			}, nil
		},
	}
}

// generateSelfSignedCert generates a self-signed certificate for development
func (s *Server) generateSelfSignedCert(domain string) (*tls.Certificate, error) {
	// Check if we already have a cached self-signed cert for this domain
	certPath := filepath.Join(s.cfg.CertDir, domain+"-dev.crt")
	keyPath := filepath.Join(s.cfg.CertDir, domain+"-dev.key")

	// Try to load existing cert
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			certPEM, _ := os.ReadFile(certPath)
			keyPEM, _ := os.ReadFile(keyPath)
			cert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err == nil {
				return &cert, nil
			}
		}
	}

	// Generate new self-signed certificate
	return s.createSelfSignedCert(domain, certPath, keyPath)
}

func (s *Server) createSelfSignedCert(domain, certPath, keyPath string) (*tls.Certificate, error) {
	// Generate private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Nexo Dev"},
			CommonName:   domain,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain, "*." + domain},
	}

	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	// Encode certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode private key
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	// Save to disk
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &cert, nil
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
	if s.trafficMgr != nil {
		s.trafficMgr.Stop()
	}
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *Server) handleHTTPS() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

		host := s.extractHost(r)
		if host == "" {
			http.Error(w, "Invalid host", http.StatusBadRequest)
			return
		}

		// Record traffic
		if s.trafficMgr != nil {
			s.trafficMgr.Record(traffic.RequestRecord{
				Timestamp: time.Now(),
				Domain:    host,
				IP:        s.getClientIP(r),
				Method:    r.Method,
				Path:      r.URL.Path,
				IsHTTPS:   r.TLS != nil,
				UserAgent: r.UserAgent(),
			})
		}

		// Handle OAuth2 routes if auth is enabled
		if s.authm != nil && s.authm.Enabled() && strings.HasPrefix(r.URL.Path, "/oauth2/") {
			if s.authm.HandleOAuth2(w, r, host) {
				return
			}
		}

		h, cfg := s.findHandlerWithConfig(host)
		if h == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(domainNotConfiguredHTML))
			return
		}

		// Check authentication if required
		if cfg != nil && cfg.Auth && s.authm != nil && s.authm.Enabled() {
			result := s.authm.CheckAuth(r)
			if result.User == "" {
				s.authm.RedirectToAuth(w, r, host)
				return
			}
			// Refresh session if needed (silent renewal)
			if result.NeedRefresh {
				s.authm.RefreshSession(w, result.User)
			}
			// Add user info to request headers for upstream
			r.Header.Set("X-Auth-User", result.User)
		}

		h.ServeHTTP(w, r)
	})
}

func (s *Server) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

func (s *Server) extractHost(r *http.Request) string {
	h := strings.ToLower(r.Host)
	if !strings.Contains(h, ":") {
		return h
	}

	host, _, err := net.SplitHostPort(h)
	if err != nil {
		return ""
	}
	return host
}

func (s *Server) findHandlerWithConfig(host string) (*proxy.Handler, *proxy.Config) {
	s.mu.RLock()
	h, ok := s.proxies[host]
	s.mu.RUnlock()

	if ok {
		return h, s.cfg.Proxies[host]
	}

	if wild, ok := s.cfg.GetWildcardDomain(host); ok {
		s.mu.RLock()
		h, ok = s.proxies[wild]
		s.mu.RUnlock()
		if ok {
			return h, s.cfg.Proxies[wild]
		}
	}

	return nil, nil
}

func (s *Server) loadProxies(reload bool) error {
	if !reload {
		return s.loadAllProxies()
	}
	return s.loadProxiesIncremental()
}

func (s *Server) loadAllProxies() error {
	new := make(map[string]*proxy.Handler)

	for d, cfg := range s.cfg.Proxies {
		if err := s.setupProxy(d, cfg, new); err != nil {
			continue
		}
	}

	s.mu.Lock()
	s.proxies = new
	s.mu.Unlock()

	return nil
}

func (s *Server) loadProxiesIncremental() error {
	s.mu.RLock()
	currentDomains := make(map[string]bool)
	for d := range s.proxies {
		currentDomains[d] = true
	}
	s.mu.RUnlock()

	newDomains := make(map[string]bool)
	for d := range s.cfg.Proxies {
		newDomains[d] = true
	}

	var added, updated, removed int

	for d, cfg := range s.cfg.Proxies {
		if !currentDomains[d] {
			handler, err := s.createProxyHandler(d, cfg)
			if err != nil {
				log.Error("Failed to add proxy", "domain", d, "err", err)
				continue
			}
			s.mu.Lock()
			s.proxies[d] = handler
			s.mu.Unlock()
			added++
			log.Info("Proxy added", "domain", d)
		} else if s.proxyConfigChanged(d, cfg) {
			handler, err := s.createProxyHandler(d, cfg)
			if err != nil {
				log.Error("Failed to update proxy", "domain", d, "err", err)
				continue
			}
			s.mu.Lock()
			s.proxies[d] = handler
			s.mu.Unlock()
			updated++
			log.Info("Proxy updated", "domain", d)
		}
	}

	s.mu.Lock()
	for d := range currentDomains {
		if !newDomains[d] {
			delete(s.proxies, d)
			removed++
			log.Info("Proxy removed", "domain", d)
		}
	}
	s.mu.Unlock()

	log.Info("Incremental reload completed", "added", added, "updated", updated, "removed", removed)
	return nil
}

func (s *Server) proxyConfigChanged(domain string, newCfg *proxy.Config) bool {
	s.mu.RLock()
	oldHandler, ok := s.proxies[domain]
	s.mu.RUnlock()
	if !ok {
		return true
	}
	return oldHandler.ConfigChanged(newCfg)
}

func (s *Server) createProxyHandler(domain string, cfg *proxy.Config) (*proxy.Handler, error) {
	if cfg.Redirect == "" && cfg.Upstream == "" {
		return nil, fmt.Errorf("either upstream or redirect must be configured for domain %s", domain)
	}

	target := proxy.EnsureSchema(orStr(cfg.Redirect, cfg.Upstream))

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("error parsing upstream URL for %s: %v", domain, err)
	}

	if err := proxy.CheckTarget(u); err != nil {
		return nil, fmt.Errorf("upstream not accessible for %s: %v", domain, err)
	}

	if err := s.handleCertObtain(domain, false); err != nil {
		return nil, err
	}

	handler := proxy.New(cfg, domain)
	if handler == nil {
		return nil, fmt.Errorf("failed to create proxy handler for domain %s", domain)
	}
	return handler, nil
}

func (s *Server) setupProxy(domain string, cfg *proxy.Config, proxies map[string]*proxy.Handler) error {
	if cfg.Redirect == "" && cfg.Upstream == "" {
		return fmt.Errorf("either upstream or redirect must be configured for domain %s", domain)
	}

	target := proxy.EnsureSchema(orStr(cfg.Redirect, cfg.Upstream))

	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("error parsing upstream URL for %s: %v", domain, err)
	}

	if err := proxy.CheckTarget(u); err != nil {
		return fmt.Errorf("upstream not accessible for %s: %v", domain, err)
	}

	if err := s.handleCertObtain(domain, false); err != nil {
		return err
	}

	proxies[domain] = proxy.New(cfg, domain)
	return nil
}

// handleCertObtain handles certificate obtaining with proper error handling and logging
func (s *Server) handleCertObtain(domain string, isRetry bool) error {
	d := domain
	if wild, ok := s.cfg.GetWildcardDomain(domain); ok {
		d = wild
	}

	// First check if we already have a valid certificate
	cert, err := s.certm.GetCertificate(&tls.ClientHelloInfo{ServerName: d})
	if err == nil && cert != nil && !needsRenewal(cert) {
		if isRetry {
			// If this is a retry and we have a valid cert, remove it from failed certs
			delete(s.failCerts, domain)
			log.Info("Found valid certificate during retry", "domain", d)
		}
		return nil
	}

	// Need to obtain a new certificate
	if err := s.certm.ObtainCert(d); err != nil {
		if isRetry {
			s.failCerts[domain] = time.Now()
			log.Error("Failed to obtain certificate (retry)", "domain", d, "err", err)
		} else {
			s.addFailedCert(domain, err)
			log.Error("Failed to obtain certificate", "domain", d, "err", err)
		}
		return err
	}

	if isRetry {
		delete(s.failCerts, domain)
		log.Info("Successfully obtained certificate (retry)", "domain", d)
	} else {
		log.Info("Successfully obtained certificate", "domain", d)
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
			ds := make([]string, 0, len(s.proxies))
			for d := range s.proxies {
				ds = append(ds, d)
			}
			s.mu.RUnlock()

			for _, d := range ds {
				s.handleCertObtain(d, false)
			}

			s.certm.SetLastRenewalCheck(time.Now())
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
				if event.Name == s.cfgPath && event.Op&fsnotify.Write == fsnotify.Write {
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

	if s.cfgPath != "" {
		return watcher.Add(filepath.Dir(s.cfgPath))
	}

	return nil
}

// Reload reloads the configuration and updates the proxies
func (s *Server) Reload() error {
	// Reload configuration file
	newCfg, err := config.Load(s.cfgPath)
	if err != nil {
		return fmt.Errorf("failed to reload config: %v", err)
	}

	s.cfg = newCfg
	if err := s.loadProxies(true); err != nil {
		return fmt.Errorf("failed to load proxies: %v", err)
	}

	// Update auth manager's allowed hosts if auth is enabled
	if s.authm != nil {
		allowedHosts := make([]string, 0, len(newCfg.Proxies))
		for domain := range newCfg.Proxies {
			allowedHosts = append(allowedHosts, domain)
		}
		s.authm.UpdateAllowedHosts(allowedHosts)

		// Also update secret key if it changed
		if newCfg.Auth.SecretKey != "" {
			s.authm.UpdateSecretKey(newCfg.Auth.SecretKey)
		}
	}

	return nil
}

func orStr(a, b string) string {
	if a != "" {
		return a
	}

	return b
}

// generateSecretKey generates a random 32-byte secret key
func generateSecretKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand should never fail on modern systems
		// If it does, something is seriously wrong - panic to avoid insecure fallback
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// saveConfig saves the configuration to file
func saveConfig(cfg *config.Config, cfgPath string) error {
	if cfgPath == "" {
		return fmt.Errorf("config path not specified")
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(cfgPath, data, 0644)
}
