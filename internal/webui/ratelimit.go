package webui

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter provides IP-based rate limiting using token bucket algorithm
type RateLimiter struct {
	visitors map[string]*visitor
	mu       sync.RWMutex
	config   *RateLimitConfig
}

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimitConfig configuration for rate limiting
type RateLimitConfig struct {
	Enabled  bool
	Requests int
	Window   time.Duration
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(cfg *RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		config:   cfg,
	}
	go rl.cleanupVisitors()
	return rl
}

// Allow checks if the IP is allowed to make a request
func (rl *RateLimiter) Allow(ip string) bool {
	if !rl.config.Enabled {
		return true
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	if !exists {
		// Create new limiter: requests per window
		limit := rate.Every(rl.config.Window / time.Duration(rl.config.Requests))
		rl.visitors[ip] = &visitor{
			limiter:  rate.NewLimiter(limit, rl.config.Requests),
			lastSeen: time.Now(),
		}
		v = rl.visitors[ip]
	}

	v.lastSeen = time.Now()
	return v.limiter.Allow()
}

// Middleware returns an HTTP middleware for rate limiting
func (rl *RateLimiter) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		if !rl.Allow(ip) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// cleanupVisitors periodically removes stale entries
func (rl *RateLimiter) cleanupVisitors() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastSeen) > rl.config.Window*2 {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// getClientIP extracts client IP from request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := findComma(xff); idx != -1 {
			return trimSpace(xff[:idx])
		}
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip, _, _ := splitHostPort(r.RemoteAddr)
	return ip
}

// Helper functions to avoid importing strings package
func findComma(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func splitHostPort(hostport string) (host, port string, err error) {
	// Simple implementation
	for i := len(hostport) - 1; i >= 0; i-- {
		if hostport[i] == ':' {
			return hostport[:i], hostport[i+1:], nil
		}
	}
	return hostport, "", nil
}
