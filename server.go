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
	ctx context.Context
	c   context.CancelFunc

	proxies map[string]*httputil.ReverseProxy

	certm *CertManager

	failed   map[string]time.Time
	failedmu sync.RWMutex

	mu sync.RWMutex
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
		certm:   NewCertManager(certConfig),
		proxies: make(map[string]*httputil.ReverseProxy),
		ctx:     ctx,
		c:       cancel,
		failed:  make(map[string]time.Time),
	}

	// Start certificate renewal goroutine
	go s.renewCerts()

	// Start retry failed certificates goroutine
	go s.retryCerts()

	// Setup config file watcher
	gViper.OnConfigChange(func(e fsnotify.Event) {
		log.Info("Config file changed", "file", e.Name)
		if err := s.reload(); err != nil {
			log.Error("Error reloading config", "err", err)
		}
	})
	gViper.WatchConfig()

	return s
}

func (s *Server) Stop() {
	if s.c != nil {
		s.c()
	}
}

func (s *Server) Start() error {
	// Load proxy configurations
	if err := s.loadProxies(); err != nil {
		log.Error("Failed to load proxy configs", "err", err)
		return err
	}

	// Start HTTPS server
	server := &http.Server{
		Addr:    ":443",
		Handler: s.handleHTTPS(),
		TLSConfig: &tls.Config{
			GetCertificate: s.certm.GetCertificate,
		},
	}

	return server.ListenAndServeTLS("", "")
}

func (s *Server) reload() error {
	// 重新评估失败的证书记录
	s.checkFailedCerts()

	// Reload proxy configurations
	// loadProxies will handle the atomic swap of the proxy map
	// only after successfully loading all new configurations
	return s.loadProxies()
}
