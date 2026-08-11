package webui

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/abcdlsj/nexo/pkg/auth"
	"github.com/abcdlsj/nexo/pkg/cert"
	"github.com/abcdlsj/nexo/pkg/config"
	"github.com/abcdlsj/nexo/pkg/traffic"
	"github.com/charmbracelet/log"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

const (
	maxWebUIRequestSize   = 1 << 20 // 1 MiB is ample for all management forms.
	trafficAPIRecordLimit = 100
)

var (
	errRouteNotFound = errors.New("route not found")
	errDomainExists  = errors.New("domain already exists")
	errInvalidForm   = errors.New("invalid route form")
)

var (
	//go:embed tmpl/*.html
	//go:embed tmpl/*.svg
	tmplFS embed.FS

	tmpl = template.Must(template.New("").Funcs(template.FuncMap{
		"hasPrefix": strings.HasPrefix,
	}).ParseFS(tmplFS, "tmpl/*.html"))
)

type csrfContextKey struct{}

type loginAttempt struct {
	count       int
	lastAttempt time.Time
	lockedUntil *time.Time
}

type Handler struct {
	configs        *configStore
	certMgr        *cert.Manager
	authMgr        *auth.Manager
	rateLimiter    *RateLimiter
	loginAttempts  map[string]*loginAttempt
	loginMu        sync.RWMutex
	trafficMgr     *traffic.Manager
	routeDiscovery *routeDiscoverer
}

func New(cfg *config.Config, cfgPath string, certMgr *cert.Manager, authMgr *auth.Manager, onChange func() error, trafficMgr *traffic.Manager) *Handler {
	rlConfig := &RateLimitConfig{
		Enabled:  cfg.Security.RateLimitEnabled,
		Requests: cfg.Security.RateLimitRequests,
		Window:   time.Duration(cfg.Security.RateLimitWindow) * time.Second,
	}
	if rlConfig.Requests == 0 {
		rlConfig.Requests = 100
	}
	if rlConfig.Window == 0 {
		rlConfig.Window = time.Minute
	}

	handler := &Handler{
		configs:        newConfigStore(cfg, cfgPath, onChange),
		certMgr:        certMgr,
		authMgr:        authMgr,
		rateLimiter:    NewRateLimiter(rlConfig),
		loginAttempts:  make(map[string]*loginAttempt),
		trafficMgr:     trafficMgr,
		routeDiscovery: newRouteDiscoverer(),
	}

	// Start cleanup goroutine for login attempts
	go handler.cleanupLoginAttempts()

	return handler
}

func (h *Handler) config() *config.Config {
	if h == nil || h.configs == nil {
		return &config.Config{}
	}
	return h.configs.snapshot()
}

// SetConfig publishes a new immutable snapshot after an external reload.
func (h *Handler) SetConfig(cfg *config.Config) {
	if h == nil {
		return
	}
	if h.configs == nil {
		h.configs = newConfigStore(cfg, "", nil)
		return
	}
	h.configs.replace(cfg)
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Public routes
	mux.HandleFunc("/login", h.securityMiddleware(h.handleLogin))
	mux.HandleFunc("/favicon.ico", h.securityMiddleware(h.handleFavicon))
	mux.HandleFunc("/favicon.svg", h.securityMiddleware(h.handleFavicon))

	// Protected routes - wrap with auth middleware
	protected := func(next http.HandlerFunc) http.HandlerFunc {
		return h.securityMiddleware(h.authMiddleware(next))
	}
	mux.HandleFunc("/", protected(h.handleDashboard))
	mux.HandleFunc("/logout", protected(h.handleLogout))
	mux.HandleFunc("/proxies", protected(h.handleProxies))
	mux.HandleFunc("/proxies/add", protected(h.handleAddProxy))
	mux.HandleFunc("/proxies/update", protected(h.handleUpdateProxy))
	mux.HandleFunc("/proxies/delete", protected(h.handleDeleteProxy))
	mux.HandleFunc("/certs", protected(h.handleCerts))
	mux.HandleFunc("/certs/renew", protected(h.handleRenewCert))
	mux.HandleFunc("/config", protected(h.handleConfig))
	mux.HandleFunc("/config/update", protected(h.handleUpdateConfig))
	mux.HandleFunc("/config/wildcard/add", protected(h.handleAddWildcard))
	mux.HandleFunc("/config/wildcard/delete", protected(h.handleDeleteWildcard))
	mux.HandleFunc("/config/secret-key/regenerate", protected(h.handleRegenerateSecretKey))
	mux.HandleFunc("/config/security/update", protected(h.handleUpdateSecurity))

	// Traffic routes
	mux.HandleFunc("/traffic", protected(h.handleTraffic))
	mux.HandleFunc("/api/traffic", protected(h.handleTrafficAPI))
	mux.HandleFunc("/api/route-icon", protected(h.handleRouteIcon))
}

func (h *Handler) securityMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: http: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cache-Control", "no-store")
		if h.config().IsIPBlocked(getClientIP(r)) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, maxWebUIRequestSize)
		}
		next(w, r)
	}
}

// authMiddleware checks if user is authenticated and validates CSRF for POST
func (h *Handler) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.config().WebUI.Password != "" {
			cookie, err := r.Cookie("nexo_session")
			if err != nil || !h.validateSession(cookie.Value) {
				http.Redirect(w, r, "/login?redirect="+url.QueryEscape(safeLocalRedirect(r.URL.RequestURI())), http.StatusSeeOther)
				return
			}
		}

		// CSRF validation for state-changing requests
		if r.Method == http.MethodPost {
			csrfCookie, err := r.Cookie("nexo_csrf")
			csrfForm := r.FormValue("csrf_token")
			if err != nil || csrfForm == "" || csrfCookie.Value != csrfForm || !h.validateCSRFToken(csrfForm) {
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}
		}

		token := h.getOrCreateCSRFToken(w, r)
		ctx := context.WithValue(r.Context(), csrfContextKey{}, token)
		next(w, r.WithContext(ctx))
	}
}

// validateSession validates the session token using HMAC
func (h *Handler) validateSession(token string) bool {
	if h.config().WebUI.Password == "" {
		return false
	}
	// Token format: timestamp:nonce:signature
	parts := strings.Split(token, ":")
	if len(parts) != 3 {
		return false
	}

	timestamp := parts[0]
	nonce := parts[1]
	signature := parts[2]

	// Check if timestamp is within 24 hours
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	now := time.Now().Unix()
	if ts > now+60 || now-ts > 86400 {
		return false
	}

	// Verify HMAC signature using password as key
	data := timestamp + ":" + nonce
	mac := hmac.New(sha256.New, h.csrfKey())
	mac.Write([]byte(data))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	return subtle.ConstantTimeCompare([]byte(signature), []byte(expectedSig)) == 1
}

// generateSessionToken generates a new signed session token with random nonce
func (h *Handler) generateSessionToken() string {
	// Generate random nonce for additional entropy
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		// crypto/rand should never fail on modern systems
		// If it does, panic to avoid insecure fallback
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonceStr := hex.EncodeToString(nonce)

	// Token format: timestamp:nonce:signature
	data := timestamp + ":" + nonceStr
	mac := hmac.New(sha256.New, h.csrfKey())
	mac.Write([]byte(data))
	signature := hex.EncodeToString(mac.Sum(nil))

	return data + ":" + signature
}

func (h *Handler) generateCSRFToken() string {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	nonceStr := hex.EncodeToString(nonce)
	mac := hmac.New(sha256.New, []byte(h.config().WebUI.Password))
	mac.Write([]byte(nonceStr))
	return nonceStr + ":" + hex.EncodeToString(mac.Sum(nil))
}

func (h *Handler) validateCSRFToken(token string) bool {
	parts := strings.Split(token, ":")
	if len(parts) != 2 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(h.config().WebUI.Password))
	mac.Write([]byte(parts[0]))
	expected := hex.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expected)) == 1
}

func (h *Handler) getOrCreateCSRFToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie("nexo_csrf"); err == nil && h.validateCSRFToken(c.Value) {
		return c.Value
	}
	token := h.generateCSRFToken()
	http.SetCookie(w, &http.Cookie{
		Name:     "nexo_csrf",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsSecure(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})
	return token
}

func (h *Handler) csrfKey() []byte {
	cfg := h.config()
	if cfg.WebUI.Password != "" {
		return []byte(cfg.WebUI.Password)
	}
	return []byte(cfg.Auth.SecretKey)
}

func requestIsSecure(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func safeLocalRedirect(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	return u.RequestURI()
}

func (h *Handler) newPageData(r *http.Request, activeNav string) PageData {
	csrfToken, _ := r.Context().Value(csrfContextKey{}).(string)
	return PageData{
		ActiveNav: activeNav,
		Config:    h.config(),
		CSRFToken: csrfToken,
	}
}

// handleLogin handles login page and form submission
func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	// If no password is configured, redirect to home
	if h.config().WebUI.Password == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Check rate limit
	clientIP := getClientIP(r)
	if !h.rateLimiter.Allow(clientIP) {
		http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
		return
	}

	csrfToken := h.getOrCreateCSRFToken(w, r)

	data := struct {
		PageData
		Error    string
		Redirect string
		Locked   bool
		LockTime int // minutes
	}{
		PageData: PageData{
			ActiveNav: "",
			Config:    h.config(),
			CSRFToken: csrfToken,
		},
		Redirect: safeLocalRedirect(r.URL.Query().Get("redirect")),
	}

	if r.Method == http.MethodPost {
		if csrfCookie, err := r.Cookie("nexo_csrf"); err != nil || r.FormValue("csrf_token") != csrfCookie.Value || !h.validateCSRFToken(r.FormValue("csrf_token")) {
			data.Error = "Invalid request"
			if err := tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
				log.Error("Failed to render login", "err", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")
		redirect := safeLocalRedirect(r.FormValue("redirect"))

		// Check if account is locked
		if allowed, lockDuration := h.checkLoginAllowed(clientIP, username); !allowed {
			data.Locked = true
			data.LockTime = int(lockDuration.Minutes()) + 1
			data.Error = fmt.Sprintf("Account locked. Please try again in %d minutes.", data.LockTime)
		} else if h.validateCredentials(username, password) {
			// Success - clear failed attempts
			h.recordLoginSuccess(clientIP, username)

			// Set session cookie with signed token
			http.SetCookie(w, &http.Cookie{
				Name:     "nexo_session",
				Value:    h.generateSessionToken(),
				Path:     "/",
				HttpOnly: true,
				Secure:   requestIsSecure(r),
				SameSite: http.SameSiteStrictMode,
				MaxAge:   86400, // 24 hours
			})
			http.Redirect(w, r, redirect, http.StatusSeeOther)
			return
		} else {
			// Failed login - record attempt
			h.recordLoginFailure(clientIP, username)
			data.Error = "Invalid username or password"
		}
	}

	if err := tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
		log.Error("Failed to render login", "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// validateCredentials validates username and password
func (h *Handler) validateCredentials(username, password string) bool {
	// Check username
	cfg := h.config()
	expectedUsername := cfg.WebUI.Username
	if expectedUsername == "" {
		expectedUsername = "admin"
	}
	if subtle.ConstantTimeCompare([]byte(username), []byte(expectedUsername)) != 1 {
		return false
	}

	// Check password using bcrypt
	err := bcrypt.CompareHashAndPassword([]byte(cfg.WebUI.Password), []byte(password))
	return err == nil
}

// handleLogout handles logout
func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "nexo_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsSecure(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

type PageData struct {
	ActiveNav string
	Config    *config.Config
	CSRFToken string
	Demo      bool
}

func (h *Handler) render404(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	data := PageData{
		ActiveNav: "",
		Config:    h.config(),
	}
	if err := tmpl.ExecuteTemplate(w, "404.html", data); err != nil {
		log.Error("Failed to render 404", "err", err)
		http.Error(w, "404 Not Found", http.StatusNotFound)
	}
}

type CertsData struct {
	PageData
	Wildcards   []string
	Certs       []CertInfo
	LastRenewal string
}

func (h *Handler) handleCerts(w http.ResponseWriter, r *http.Request) {
	cfg := h.config()
	var lastRenewal string
	if h.certMgr != nil {
		t := h.certMgr.LastRenewalCheck()
		if !t.IsZero() {
			lastRenewal = t.Format("2006-01-02 15:04:05")
		}
	}

	data := CertsData{
		PageData:    h.newPageData(r, "certs"),
		Wildcards:   cfg.Wildcards,
		Certs:       h.getCertInfo(cfg),
		LastRenewal: lastRenewal,
	}

	if err := tmpl.ExecuteTemplate(w, "certs.html", data); err != nil {
		log.Error("Failed to render certs", "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *Handler) handleRenewCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/certs", http.StatusSeeOther)
		return
	}

	domain := r.FormValue("domain")
	if domain != "" && h.certMgr != nil {
		if err := h.certMgr.ObtainCert(domain); err != nil {
			log.Error("Failed to renew certificate", "domain", domain, "err", err)
		} else {
			log.Info("Certificate renewed", "domain", domain)
		}
	}

	http.Redirect(w, r, "/certs", http.StatusSeeOther)
}

type ConfigData struct {
	PageData
	Message        string
	Error          string
	RawConfig      string
	MaskedAPIToken string
}

func (h *Handler) handleConfig(w http.ResponseWriter, r *http.Request) {
	cfg := h.config()
	data := ConfigData{
		PageData:       h.newPageData(r, "config"),
		Message:        r.URL.Query().Get("message"),
		Error:          r.URL.Query().Get("error"),
		MaskedAPIToken: maskAPIToken(cfg.Cloudflare.APIToken),
	}

	if h.configs.path != "" {
		content, err := os.ReadFile(h.configs.path)
		if err == nil {
			data.RawConfig = maskSensitiveConfig(string(content))
		}
	}

	if err := tmpl.ExecuteTemplate(w, "config.html", data); err != nil {
		log.Error("Failed to render config", "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *Handler) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/config", http.StatusSeeOther)
		return
	}

	if err := h.configs.update(func(next *config.Config) error {
		switch r.FormValue("section") {
		case "basic":
			if email := strings.TrimSpace(r.FormValue("email")); email != "" {
				next.Email = email
			}
		case "cloudflare":
			if token := strings.TrimSpace(r.FormValue("api_token")); token != "" {
				next.Cloudflare.APIToken = token
			}
		}
		return nil
	}); err != nil {
		log.Error("Failed to save config", "err", err)
		http.Redirect(w, r, "/config?message=Failed+to+save+config", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/config?message=Configuration+saved", http.StatusSeeOther)
}

func (h *Handler) handleAddWildcard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/config", http.StatusSeeOther)
		return
	}

	wildcard := strings.TrimSpace(r.FormValue("wildcard"))
	if validDomain(wildcard, true) {
		if err := h.configs.update(func(next *config.Config) error {
			if !slices.Contains(next.Wildcards, wildcard) {
				next.Wildcards = append(next.Wildcards, wildcard)
			}
			return nil
		}); err != nil {
			log.Error("Failed to save config", "err", err)
			http.Redirect(w, r, "/config?error=save_failed", http.StatusSeeOther)
			return
		}
	}

	http.Redirect(w, r, "/config", http.StatusSeeOther)
}

func (h *Handler) handleDeleteWildcard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/config", http.StatusSeeOther)
		return
	}

	wildcard := r.FormValue("wildcard")
	if wildcard != "" {
		if err := h.configs.update(func(next *config.Config) error {
			next.Wildcards = slices.DeleteFunc(next.Wildcards, func(w string) bool { return w == wildcard })
			return nil
		}); err != nil {
			log.Error("Failed to save config", "err", err)
			http.Redirect(w, r, "/config?error=save_failed", http.StatusSeeOther)
			return
		}
	}

	http.Redirect(w, r, "/config", http.StatusSeeOther)
}

func (h *Handler) handleRegenerateSecretKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/config", http.StatusSeeOther)
		return
	}

	// Generate new secret key
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Error("Failed to generate secret key", "err", err)
		http.Redirect(w, r, "/config?error=Failed+to+generate+secret+key", http.StatusSeeOther)
		return
	}
	newKey := base64.RawURLEncoding.EncodeToString(b)

	if err := h.configs.update(func(next *config.Config) error {
		next.Auth.SecretKey = newKey
		return nil
	}); err != nil {
		log.Error("Failed to save config", "err", err)
		http.Redirect(w, r, "/config?error=Failed+to+save+config", http.StatusSeeOther)
		return
	}
	if h.authMgr != nil {
		h.authMgr.UpdateSecretKey(newKey)
	}

	log.Info("Secret key regenerated")
	http.Redirect(w, r, "/config?message=Secret+key+regenerated.+All+users+have+been+logged+out.", http.StatusSeeOther)
}

func (h *Handler) handleFavicon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := tmplFS.ReadFile("tmpl/nexo.svg")
	if err != nil {
		log.Error("Failed to read favicon", "err", err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}

func (h *Handler) getCertInfo(cfg *config.Config) []CertInfo {
	var certs []CertInfo

	if cfg.CertDir == "" {
		return certs
	}

	domains := make(map[string]bool)
	for domain := range cfg.Proxies {
		domains[domain] = true
	}
	for _, w := range cfg.Wildcards {
		domains[w] = true
	}

	for domain := range domains {
		info := h.getCertForDomain(cfg, domain)
		if info.Domain != "" {
			certs = append(certs, info)
		}
	}

	return certs
}

func (h *Handler) getCertForDomain(cfg *config.Config, domain string) CertInfo {
	info := CertInfo{
		Domain: domain,
		Status: "error",
	}

	// For wildcard domains like *.example.com, look for example.com.crt
	if strings.HasPrefix(domain, "*.") {
		baseDomain := domain[2:]
		certFile := filepath.Join(cfg.CertDir, baseDomain+".crt")
		keyFile := filepath.Join(cfg.CertDir, baseDomain+".key")
		return h.readCertInfo(domain, certFile, keyFile)
	}

	// For regular domains, first try exact match
	certFile := filepath.Join(cfg.CertDir, domain+".crt")
	keyFile := filepath.Join(cfg.CertDir, domain+".key")
	if _, err := os.Stat(certFile); err == nil {
		return h.readCertInfo(domain, certFile, keyFile)
	}

	// If no exact match, try wildcard match using config method
	if wild, ok := cfg.GetWildcardDomain(domain); ok {
		baseDomain := wild[2:] // Remove "*." prefix
		certFile = filepath.Join(cfg.CertDir, baseDomain+".crt")
		keyFile = filepath.Join(cfg.CertDir, baseDomain+".key")
		if _, err := os.Stat(certFile); err == nil {
			info = h.readCertInfo(domain, certFile, keyFile)
			info.UsesWildcard = true
			info.WildcardDomain = wild
			return info
		}
	}

	return info
}

func (h *Handler) readCertInfo(domain, certFile, keyFile string) CertInfo {
	info := CertInfo{
		Domain: domain,
		Status: "error",
	}

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		return info
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return info
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return info
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return info
	}

	info.Issuer = cert.Issuer.CommonName
	info.ExpiryDate = cert.NotAfter.Format("2006-01-02")
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	info.DaysLeft = daysLeft

	if daysLeft < 0 {
		info.Status = "error"
	} else if daysLeft < 30 {
		info.Status = "expiring"
	} else {
		info.Status = "valid"
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		info.Status = "error"
	}

	return info
}

// checkLoginAllowed checks if login is allowed for the IP/username
func (h *Handler) checkLoginAllowed(ip, username string) (bool, time.Duration) {
	key := ip + ":" + username

	h.loginMu.RLock()
	attempt, exists := h.loginAttempts[key]
	h.loginMu.RUnlock()

	if !exists {
		return true, 0
	}

	// Check if locked
	if attempt.lockedUntil != nil && time.Now().Before(*attempt.lockedUntil) {
		return false, time.Until(*attempt.lockedUntil)
	}

	return true, 0
}

// recordLoginFailure records a failed login attempt
func (h *Handler) recordLoginFailure(ip, username string) {
	key := ip + ":" + username

	h.loginMu.Lock()
	defer h.loginMu.Unlock()

	attempt, exists := h.loginAttempts[key]
	if !exists {
		attempt = &loginAttempt{}
		h.loginAttempts[key] = attempt
	}

	attempt.count++
	attempt.lastAttempt = time.Now()

	cfg := h.config()
	maxAttempts := cfg.Security.MaxLoginAttempts
	if maxAttempts == 0 {
		maxAttempts = 5
	}

	if attempt.count >= maxAttempts {
		lockoutMinutes := cfg.Security.LoginLockoutMinutes
		if lockoutMinutes == 0 {
			lockoutMinutes = 30
		}
		lockedUntil := time.Now().Add(time.Duration(lockoutMinutes) * time.Minute)
		attempt.lockedUntil = &lockedUntil
		log.Warn("Account locked due to failed login attempts", "ip", ip, "username", username, "attempts", attempt.count)
	}
}

// recordLoginSuccess clears login failures on success
func (h *Handler) recordLoginSuccess(ip, username string) {
	key := ip + ":" + username

	h.loginMu.Lock()
	delete(h.loginAttempts, key)
	h.loginMu.Unlock()
}

// SetTrafficManager sets the traffic manager
func (h *Handler) SetTrafficManager(tm *traffic.Manager) {
	h.trafficMgr = tm
}

// cleanupLoginAttempts periodically removes stale login attempt records
func (h *Handler) cleanupLoginAttempts() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		h.loginMu.Lock()
		for key, attempt := range h.loginAttempts {
			// Remove records older than 24 hours
			if time.Since(attempt.lastAttempt) > 24*time.Hour {
				delete(h.loginAttempts, key)
			}
		}
		h.loginMu.Unlock()
	}
}

// handleUpdateSecurity handles security configuration updates
func (h *Handler) handleUpdateSecurity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/config", http.StatusSeeOther)
		return
	}

	if err := h.configs.update(func(next *config.Config) error {
		next.Security.RateLimitEnabled = r.FormValue("rate_limit_enabled") == "on"
		if value, err := strconv.Atoi(r.FormValue("rate_limit_requests")); err == nil && value > 0 {
			next.Security.RateLimitRequests = value
		}
		if value, err := strconv.Atoi(r.FormValue("rate_limit_window")); err == nil && value > 0 {
			next.Security.RateLimitWindow = value
		}
		if value, err := strconv.Atoi(r.FormValue("max_login_attempts")); err == nil && value > 0 {
			next.Security.MaxLoginAttempts = value
		}
		if value, err := strconv.Atoi(r.FormValue("login_lockout_minutes")); err == nil && value > 0 {
			next.Security.LoginLockoutMinutes = value
		}
		return nil
	}); err != nil {
		log.Error("Failed to save security config", "err", err)
		http.Redirect(w, r, "/config?error=Failed+to+save+security+config", http.StatusSeeOther)
		return
	}
	security := h.config().Security
	h.rateLimiter.UpdateConfig(RateLimitConfig{
		Enabled:  security.RateLimitEnabled,
		Requests: security.RateLimitRequests,
		Window:   time.Duration(security.RateLimitWindow) * time.Second,
	})

	http.Redirect(w, r, "/config?message=Security+configuration+saved", http.StatusSeeOther)
}

// handleTraffic renders the traffic page
func (h *Handler) handleTraffic(w http.ResponseWriter, r *http.Request) {
	data := struct {
		PageData
	}{
		PageData: h.newPageData(r, "traffic"),
	}

	if err := tmpl.ExecuteTemplate(w, "traffic.html", data); err != nil {
		log.Error("Failed to render traffic", "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleTrafficAPI returns traffic data as JSON
func (h *Handler) handleTrafficAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.trafficMgr == nil {
		http.Error(w, "Traffic tracking not enabled", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	data := h.trafficMgr.GetRecentData(trafficAPIRecordLimit)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Error("Failed to encode traffic data", "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func validHTTPURL(raw string) bool {
	u, err := url.ParseRequestURI(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil
}

func validDomain(domain string, wildcard bool) bool {
	if wildcard {
		if !strings.HasPrefix(domain, "*.") {
			return false
		}
		domain = strings.TrimPrefix(domain, "*.")
	} else if strings.HasPrefix(domain, "*.") {
		return false
	}
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if len(domain) == 0 || len(domain) > 253 || net.ParseIP(domain) != nil {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".nexo-config-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func maskAPIToken(token string) string {
	if len(token) > 4 {
		return "••••" + token[len(token)-4:]
	}
	if token != "" {
		return "••••••••"
	}
	return ""
}

func maskSensitiveConfig(raw string) string {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(raw), &document); err != nil {
		return "# Configuration unavailable: invalid YAML"
	}
	maskSensitiveYAML(&document)
	masked, err := yaml.Marshal(&document)
	if err != nil {
		return "# Configuration unavailable"
	}
	return string(masked)
}

func maskSensitiveYAML(node *yaml.Node) {
	sensitive := map[string]bool{
		"api_token": true, "secret_key": true, "client_secret": true, "password": true,
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if sensitive[strings.ToLower(strings.TrimSpace(key.Value))] {
				value.Kind = yaml.ScalarNode
				value.Tag = "!!str"
				value.Value = "••••••••"
				value.Content = nil
				continue
			}
			maskSensitiveYAML(value)
		}
		return
	}
	for _, child := range node.Content {
		maskSensitiveYAML(child)
	}
}
