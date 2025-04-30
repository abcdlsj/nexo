package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/fsnotify/fsnotify"
)

type Server struct {
	ctx    context.Context
	cancel context.CancelFunc

	proxies map[string]*httputil.ReverseProxy

	certm *CertManager

	failCerts   map[string]time.Time
	failCertsMu sync.RWMutex

	mu sync.RWMutex
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
		certm:     NewCertManager(certConfig),
		proxies:   make(map[string]*httputil.ReverseProxy),
		ctx:       ctx,
		cancel:    cancel,
		failCerts: make(map[string]time.Time),
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
	if s.cancel != nil {
		s.cancel()
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
		Addr: ":443",
		TLSConfig: &tls.Config{
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				return &tls.Config{
					GetCertificate: s.certm.GetCertificate,
					MinVersion:     tls.VersionTLS12, // 强制使用 TLS 1.2 或更高版本
				}, nil
			},
		},
		Handler:           s.handleHTTPS(),
		ReadTimeout:       30 * time.Second,  // 读取整个请求的超时时间
		WriteTimeout:      30 * time.Second,  // 写入响应的超时时间
		IdleTimeout:       120 * time.Second, // 保持连接等待下一个请求的超时时间
		ReadHeaderTimeout: 10 * time.Second,  // 读取请求头的超时时间
		MaxHeaderBytes:    1 << 20,           // 限制请求头大小为 1MB
		ErrorLog: log.NewWithOptions(os.Stderr, log.Options{Prefix: "http"}).
			StandardLog(log.StandardLogOptions{
				ForceLevel: log.ErrorLevel,
			}),
	}

	// 启用 TCP keep-alive
	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return err
	}
	tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, server.TLSConfig)

	return server.Serve(tlsListener)
}

func (s *Server) reload() error {
	// 重新评估失败的证书记录
	s.checkFailedCerts()

	// Reload proxy configurations
	// loadProxies will handle the atomic swap of the proxy map
	// only after successfully loading all new configurations
	return s.loadProxies()
}
