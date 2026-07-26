package webui

import (
	"net"
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
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if !rl.config.Enabled {
		return true
	}

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

// UpdateConfig replaces limiter settings without racing active requests.
func (rl *RateLimiter) UpdateConfig(cfg RateLimitConfig) {
	rl.mu.Lock()
	rl.config = &cfg
	rl.visitors = make(map[string]*visitor)
	rl.mu.Unlock()
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
	// The WebUI listener is directly exposed. Trusting arbitrary forwarding
	// headers here lets attackers rotate fake IPs and bypass login throttling.
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
