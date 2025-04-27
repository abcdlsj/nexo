package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

type Server struct {
	certManager   *CertManager
	proxies       map[string]*httputil.ReverseProxy
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	failedCerts   map[string]time.Time
	failedCertsMu sync.RWMutex
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

func (s *Server) reloadConfig() error {
	s.mu.Lock()
	// Clear existing proxies
	s.proxies = make(map[string]*httputil.ReverseProxy)
	s.mu.Unlock()

	// 重新评估失败的证书记录
	s.reevaluateFailedCerts()

	// Reload proxy configurations
	return s.loadProxyConfigs()
}
