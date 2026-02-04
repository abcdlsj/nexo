package webui

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/abcdlsj/nexo/pkg/auth"
	"github.com/abcdlsj/nexo/pkg/cert"
	"github.com/abcdlsj/nexo/pkg/config"
	"github.com/abcdlsj/nexo/pkg/proxy"
	"github.com/charmbracelet/log"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

var (
	//go:embed tmpl/*.html
	//go:embed tmpl/*.ico
	tmplFS embed.FS

	tmpl = template.Must(template.New("").Funcs(template.FuncMap{
		"hasPrefix": strings.HasPrefix,
	}).ParseFS(tmplFS, "tmpl/*.html"))
)

type Handler struct {
	cfg      *config.Config
	cfgPath  string
	certMgr  *cert.Manager
	authMgr  *auth.Manager
	proxies  map[string]*proxy.Handler
	onChange func() error
}

func New(cfg *config.Config, cfgPath string, certMgr *cert.Manager, authMgr *auth.Manager, proxies map[string]*proxy.Handler, onChange func() error) *Handler {
	return &Handler{
		cfg:      cfg,
		cfgPath:  cfgPath,
		certMgr:  certMgr,
		authMgr:  authMgr,
		proxies:  proxies,
		onChange: onChange,
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Public routes
	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc("/logout", h.handleLogout)
	mux.HandleFunc("/favicon.ico", h.handleFavicon)

	// Protected routes - wrap with auth middleware
	mux.HandleFunc("/", h.authMiddleware(h.handleDashboard))
	mux.HandleFunc("/proxies", h.authMiddleware(h.handleProxies))
	mux.HandleFunc("/proxies/add", h.authMiddleware(h.handleAddProxy))
	mux.HandleFunc("/proxies/delete", h.authMiddleware(h.handleDeleteProxy))
	mux.HandleFunc("/certs", h.authMiddleware(h.handleCerts))
	mux.HandleFunc("/certs/renew", h.authMiddleware(h.handleRenewCert))
	mux.HandleFunc("/config", h.authMiddleware(h.handleConfig))
	mux.HandleFunc("/config/update", h.authMiddleware(h.handleUpdateConfig))
	mux.HandleFunc("/config/wildcard/add", h.authMiddleware(h.handleAddWildcard))
	mux.HandleFunc("/config/wildcard/delete", h.authMiddleware(h.handleDeleteWildcard))
	mux.HandleFunc("/config/secret-key/regenerate", h.authMiddleware(h.handleRegenerateSecretKey))
}

// authMiddleware checks if user is authenticated
func (h *Handler) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If no password is configured, allow access
		if h.cfg.WebUI.Password == "" {
			next(w, r)
			return
		}

		// Check session cookie
		cookie, err := r.Cookie("nexo_session")
		if err != nil || !h.validateSession(cookie.Value) {
			// Redirect to login
			http.Redirect(w, r, "/login?redirect="+r.URL.Path, http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}

// validateSession validates the session token using HMAC
func (h *Handler) validateSession(token string) bool {
	if h.cfg.WebUI.Password == "" {
		return false
	}
	// Token format: timestamp:signature
	parts := strings.Split(token, ":")
	if len(parts) != 2 {
		return false
	}

	timestamp := parts[0]
	signature := parts[1]

	// Check if timestamp is within 24 hours
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	if time.Now().Unix()-ts > 86400 {
		return false
	}

	// Verify HMAC signature using password as key
	mac := hmac.New(sha256.New, []byte(h.cfg.WebUI.Password))
	mac.Write([]byte(timestamp))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	return subtle.ConstantTimeCompare([]byte(signature), []byte(expectedSig)) == 1
}

// generateSessionToken generates a new signed session token
func (h *Handler) generateSessionToken() string {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(h.cfg.WebUI.Password))
	mac.Write([]byte(timestamp))
	signature := hex.EncodeToString(mac.Sum(nil))
	return timestamp + ":" + signature
}

// handleLogin handles login page and form submission
func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	// If no password is configured, redirect to home
	if h.cfg.WebUI.Password == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	data := struct {
		PageData
		Error    string
		Redirect string
	}{
		PageData: PageData{
			ActiveNav: "",
			Config:    h.cfg,
		},
		Redirect: r.URL.Query().Get("redirect"),
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		redirect := r.FormValue("redirect")
		if redirect == "" {
			redirect = "/"
		}

		// Validate credentials
		if h.validateCredentials(username, password) {
			// Set session cookie with signed token
			http.SetCookie(w, &http.Cookie{
				Name:     "nexo_session",
				Value:    h.generateSessionToken(),
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   86400, // 24 hours
			})
			http.Redirect(w, r, redirect, http.StatusSeeOther)
			return
		}

		data.Error = "Invalid username or password"
	}

	if err := tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
		log.Error("Failed to render login", "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// validateCredentials validates username and password
func (h *Handler) validateCredentials(username, password string) bool {
	// Check username
	expectedUsername := h.cfg.WebUI.Username
	if expectedUsername == "" {
		expectedUsername = "admin"
	}
	if subtle.ConstantTimeCompare([]byte(username), []byte(expectedUsername)) != 1 {
		return false
	}

	// Check password using bcrypt
	err := bcrypt.CompareHashAndPassword([]byte(h.cfg.WebUI.Password), []byte(password))
	return err == nil
}

// handleLogout handles logout
func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "nexo_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

type PageData struct {
	ActiveNav string
	Config    *config.Config
}

type DashboardData struct {
	PageData
	Stats struct {
		TotalProxies  int
		ActiveProxies int
		RedirectCount int
		CertCount     int
	}
	Proxies map[string]*proxy.Config
	Certs   []CertInfo
}

type CertInfo struct {
	Domain         string
	Status         string
	ExpiryDate     string
	DaysLeft       int
	Issuer         string
	UsesWildcard   bool   // whether using a wildcard certificate
	WildcardDomain string // the wildcard domain used (if any)
}

func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	data := DashboardData{
		PageData: PageData{
			ActiveNav: "dashboard",
			Config:    h.cfg,
		},
		Proxies: h.cfg.Proxies,
	}

	data.Stats.TotalProxies = len(h.cfg.Proxies)
	for _, p := range h.cfg.Proxies {
		if p.Upstream != "" {
			data.Stats.ActiveProxies++
		} else if p.Redirect != "" {
			data.Stats.RedirectCount++
		}
	}

	data.Certs = h.getCertInfo()
	data.Stats.CertCount = len(data.Certs)

	if err := tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		log.Error("Failed to render dashboard", "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

type ProxiesData struct {
	PageData
	Proxies map[string]*proxy.Config
	Message string
	Error   string
}

func (h *Handler) handleProxies(w http.ResponseWriter, r *http.Request) {
	data := ProxiesData{
		PageData: PageData{
			ActiveNav: "proxies",
			Config:    h.cfg,
		},
		Proxies: h.cfg.Proxies,
		Message: r.URL.Query().Get("message"),
		Error:   r.URL.Query().Get("error"),
	}

	if err := tmpl.ExecuteTemplate(w, "proxies.html", data); err != nil {
		log.Error("Failed to render proxies", "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *Handler) handleAddProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/proxies", http.StatusSeeOther)
		return
	}

	domain := strings.TrimSpace(r.FormValue("domain"))
	proxyType := r.FormValue("type")

	if domain == "" {
		http.Redirect(w, r, "/proxies", http.StatusSeeOther)
		return
	}

	cfg := &proxy.Config{}
	if proxyType == "proxy" {
		upstream := strings.TrimSpace(r.FormValue("upstream"))
		if upstream == "" {
			http.Redirect(w, r, "/proxies", http.StatusSeeOther)
			return
		}
		cfg.Upstream = upstream
	} else {
		redirect := strings.TrimSpace(r.FormValue("redirect"))
		if redirect == "" {
			http.Redirect(w, r, "/proxies", http.StatusSeeOther)
			return
		}
		cfg.Redirect = redirect
	}

	if h.cfg.Proxies == nil {
		h.cfg.Proxies = make(map[string]*proxy.Config)
	}
	h.cfg.Proxies[domain] = cfg

	if err := h.saveAndReload(); err != nil {
		log.Error("Failed to save config", "err", err)
		http.Redirect(w, r, "/proxies?error=save_failed", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/proxies", http.StatusSeeOther)
}

func (h *Handler) handleDeleteProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/proxies", http.StatusSeeOther)
		return
	}

	domain := r.FormValue("domain")
	if domain != "" {
		delete(h.cfg.Proxies, domain)
		if err := h.saveAndReload(); err != nil {
			log.Error("Failed to save config", "err", err)
			http.Redirect(w, r, "/proxies?error=save_failed", http.StatusSeeOther)
			return
		}
	}

	http.Redirect(w, r, "/proxies", http.StatusSeeOther)
}

type CertsData struct {
	PageData
	Wildcards   []string
	Certs       []CertInfo
	LastRenewal string
}

func (h *Handler) handleCerts(w http.ResponseWriter, r *http.Request) {
	var lastRenewal string
	if h.certMgr != nil {
		t := h.certMgr.LastRenewalCheck()
		if !t.IsZero() {
			lastRenewal = t.Format("2006-01-02 15:04:05")
		}
	}

	data := CertsData{
		PageData: PageData{
			ActiveNav: "certs",
			Config:    h.cfg,
		},
		Wildcards:   h.cfg.Wildcards,
		Certs:       h.getCertInfo(),
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
	Message   string
	Error     string
	RawConfig string
}

func (h *Handler) handleConfig(w http.ResponseWriter, r *http.Request) {
	data := ConfigData{
		PageData: PageData{
			ActiveNav: "config",
			Config:    h.cfg,
		},
		Message: r.URL.Query().Get("message"),
		Error:   r.URL.Query().Get("error"),
	}

	if h.cfgPath != "" {
		content, err := os.ReadFile(h.cfgPath)
		if err == nil {
			data.RawConfig = string(content)
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

	section := r.FormValue("section")
	switch section {
	case "basic":
		email := strings.TrimSpace(r.FormValue("email"))
		if email != "" {
			h.cfg.Email = email
		}
	case "cloudflare":
		token := strings.TrimSpace(r.FormValue("api_token"))
		if token != "" {
			h.cfg.Cloudflare.APIToken = token
		}
	}

	if err := h.saveAndReload(); err != nil {
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
	if wildcard != "" && strings.HasPrefix(wildcard, "*.") {
		if !slices.Contains(h.cfg.Wildcards, wildcard) {
			h.cfg.Wildcards = append(h.cfg.Wildcards, wildcard)
			if err := h.saveAndReload(); err != nil {
				log.Error("Failed to save config", "err", err)
				http.Redirect(w, r, "/config?error=save_failed", http.StatusSeeOther)
				return
			}
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
		h.cfg.Wildcards = slices.DeleteFunc(h.cfg.Wildcards, func(w string) bool {
			return w == wildcard
		})
		if err := h.saveAndReload(); err != nil {
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

	h.cfg.Auth.SecretKey = newKey

	// Update auth manager's secret key so existing sessions are invalidated immediately
	if h.authMgr != nil {
		h.authMgr.UpdateSecretKey(newKey)
	}

	if err := h.saveAndReload(); err != nil {
		log.Error("Failed to save config", "err", err)
		http.Redirect(w, r, "/config?error=Failed+to+save+config", http.StatusSeeOther)
		return
	}

	log.Info("Secret key regenerated")
	http.Redirect(w, r, "/config?message=Secret+key+regenerated.+All+users+have+been+logged+out.", http.StatusSeeOther)
}

func (h *Handler) handleFavicon(w http.ResponseWriter, r *http.Request) {
	data, err := tmplFS.ReadFile("tmpl/nexon.ico")
	if err != nil {
		log.Error("Failed to read favicon", "err", err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "image/x-icon")
	w.Write(data)
}

func (h *Handler) getCertInfo() []CertInfo {
	var certs []CertInfo

	if h.cfg.CertDir == "" {
		return certs
	}

	domains := make(map[string]bool)
	for domain := range h.cfg.Proxies {
		domains[domain] = true
	}
	for _, w := range h.cfg.Wildcards {
		domains[w] = true
	}

	for domain := range domains {
		info := h.getCertForDomain(domain)
		if info.Domain != "" {
			certs = append(certs, info)
		}
	}

	return certs
}

func (h *Handler) getCertForDomain(domain string) CertInfo {
	info := CertInfo{
		Domain: domain,
		Status: "error",
	}

	// For wildcard domains like *.example.com, look for example.com.crt
	if strings.HasPrefix(domain, "*.") {
		baseDomain := domain[2:]
		certFile := filepath.Join(h.cfg.CertDir, baseDomain+".crt")
		keyFile := filepath.Join(h.cfg.CertDir, baseDomain+".key")
		return h.readCertInfo(domain, certFile, keyFile)
	}

	// For regular domains, first try exact match
	certFile := filepath.Join(h.cfg.CertDir, domain+".crt")
	keyFile := filepath.Join(h.cfg.CertDir, domain+".key")
	if _, err := os.Stat(certFile); err == nil {
		return h.readCertInfo(domain, certFile, keyFile)
	}

	// If no exact match, try wildcard match using config method
	if wild, ok := h.cfg.GetWildcardDomain(domain); ok {
		baseDomain := wild[2:] // Remove "*." prefix
		certFile = filepath.Join(h.cfg.CertDir, baseDomain+".crt")
		keyFile = filepath.Join(h.cfg.CertDir, baseDomain+".key")
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

func (h *Handler) saveAndReload() error {
	data, err := yaml.Marshal(h.cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(h.cfgPath, data, 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if h.onChange != nil {
		if err := h.onChange(); err != nil {
			return fmt.Errorf("reload: %w", err)
		}
	}
	return nil
}
