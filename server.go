package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"path/filepath"
	"sync"
	"time"

	"github.com/charmbracelet/log"
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
			log.Fatal("base_dir not found in config")
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
		log.Info("Config file changed", "file", e.Name)
		if err := s.reloadConfig(); err != nil {
			log.Error("Error reloading config", "err", err)
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
		log.Error("Failed to load proxy configs", "err", err)
		return err
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
	// 重新评估失败的证书记录
	s.reevaluateFailedCerts()

	// Reload proxy configurations
	// loadProxyConfigs will handle the atomic swap of the proxy map
	// only after successfully loading all new configurations
	return s.loadProxyConfigs()
}
