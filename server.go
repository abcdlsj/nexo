package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/log"
	"github.com/fsnotify/fsnotify"
	"golang.org/x/time/rate"
)

type limiterWithTime struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

type failureRecord struct {
	count     int
	firstFail time.Time
	lastFail  time.Time
}

type Server struct {
	ctx context.Context
	c   context.CancelFunc

	proxies map[string]*httputil.ReverseProxy

	certm *CertManager

	failCerts   map[string]time.Time
	failCertsMu sync.RWMutex

	mu sync.RWMutex

	// Rate limiter for TLS handshakes
	limiters   map[string]*limiterWithTime
	limitersMu sync.RWMutex

	// IP ban system
	failures   map[string]*failureRecord
	failuresMu sync.RWMutex
	banned     map[string]time.Time
	bannedMu   sync.RWMutex

	// 并发连接控制
	connCount   int32
	maxConns    int32
	activeConns sync.Map
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
		c:         cancel,
		failCerts: make(map[string]time.Time),
		limiters:  make(map[string]*limiterWithTime),
		failures:  make(map[string]*failureRecord),
		banned:    make(map[string]time.Time),
		maxConns:  100, // 最大并发连接数
	}

	// Start certificate renewal goroutine
	go s.renewCerts()

	// Start retry failed certificates goroutine
	go s.retryCerts()

	// Start cleanup for rate limiters
	go s.cleanupLimiters()

	// Start cleanup for failures and bans
	go s.cleanupFailuresAndBans()

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

func (s *Server) getLimiter(ip string) *rate.Limiter {
	s.limitersMu.RLock()
	lt, exists := s.limiters[ip]
	s.limitersMu.RUnlock()

	if !exists {
		lt = &limiterWithTime{
			limiter:    rate.NewLimiter(rate.Every(time.Second), 5), // 5 requests per second
			lastAccess: time.Now(),
		}
		s.limitersMu.Lock()
		s.limiters[ip] = lt
		s.limitersMu.Unlock()
		return lt.limiter
	}

	lt.lastAccess = time.Now()
	return lt.limiter
}

func (s *Server) cleanupLimiters() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.limitersMu.Lock()
			for ip, lt := range s.limiters {
				if time.Since(lt.lastAccess) > 30*time.Minute {
					delete(s.limiters, ip)
				}
			}
			s.limitersMu.Unlock()
		}
	}
}

func (s *Server) isBanned(ip string) bool {
	s.bannedMu.RLock()
	banTime, banned := s.banned[ip]
	s.bannedMu.RUnlock()

	if !banned {
		return false
	}

	if time.Since(banTime) > 1*time.Hour {
		s.bannedMu.Lock()
		delete(s.banned, ip)
		s.bannedMu.Unlock()
		return false
	}

	return true
}

func (s *Server) recordFailure(ip string) {
	s.failuresMu.Lock()
	defer s.failuresMu.Unlock()

	record, exists := s.failures[ip]
	now := time.Now()

	if !exists {
		s.failures[ip] = &failureRecord{
			count:     1,
			firstFail: now,
			lastFail:  now,
		}
		return
	}

	// Reset count if last failure was more than 5 minutes ago
	if time.Since(record.lastFail) > 5*time.Minute {
		record.count = 0
		record.firstFail = now
	}

	record.count++
	record.lastFail = now

	// Ban IP if more than 50 failures in 5 minutes
	if record.count > 50 && time.Since(record.firstFail) <= 5*time.Minute {
		s.bannedMu.Lock()
		s.banned[ip] = now
		s.bannedMu.Unlock()
		log.Warn("IP banned due to excessive failures", "ip", ip, "failures", record.count)
		delete(s.failures, ip)
	}
}

func (s *Server) cleanupFailuresAndBans() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()

			// Cleanup old failure records
			s.failuresMu.Lock()
			for ip, record := range s.failures {
				if time.Since(record.lastFail) > 30*time.Minute {
					delete(s.failures, ip)
				}
			}
			s.failuresMu.Unlock()

			// Cleanup expired bans
			s.bannedMu.Lock()
			for ip, banTime := range s.banned {
				if now.Sub(banTime) > 1*time.Hour {
					delete(s.banned, ip)
					log.Info("Ban expired", "ip", ip)
				}
			}
			s.bannedMu.Unlock()
		}
	}
}

func (s *Server) Stop() {
	if s.c != nil {
		s.c()
	}
}

func (s *Server) trackConnection(remoteAddr string) bool {
	if atomic.LoadInt32(&s.connCount) >= s.maxConns {
		return false
	}

	atomic.AddInt32(&s.connCount, 1)
	s.activeConns.Store(remoteAddr, time.Now())
	return true
}

func (s *Server) removeConnection(remoteAddr string) {
	s.activeConns.Delete(remoteAddr)
	atomic.AddInt32(&s.connCount, -1)
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
				// Extract client IP from hello.Conn
				tcpConn := hello.Conn.RemoteAddr().String()
				ip := tcpConn[:strings.LastIndex(tcpConn, ":")]

				// Check if IP is banned
				if s.isBanned(ip) {
					log.Debug("Rejected banned IP", "ip", ip)
					return nil, fmt.Errorf("ip is banned")
				}

				// Apply rate limiting
				if !s.getLimiter(ip).Allow() {
					log.Warn("Rate limit exceeded for TLS handshake", "ip", ip)
					s.recordFailure(ip)
					return nil, fmt.Errorf("rate limit exceeded")
				}

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
