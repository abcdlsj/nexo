package webui

import (
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/abcdlsj/nexo/pkg/cert"
	"github.com/abcdlsj/nexo/pkg/config"
	"github.com/abcdlsj/nexo/pkg/proxy"
	"github.com/charmbracelet/log"
	"gopkg.in/yaml.v3"
)

var (
	//go:embed tmpl/*.html
	//go:embed tmpl/*.ico
	tmplFS embed.FS

	tmpl = template.Must(template.New("").ParseFS(tmplFS, "tmpl/*.html"))
)

type Handler struct {
	cfg      *config.Config
	cfgPath  string
	certMgr  *cert.Manager
	proxies  map[string]*proxy.Handler
	onChange func() error
}

func New(cfg *config.Config, cfgPath string, certMgr *cert.Manager, proxies map[string]*proxy.Handler, onChange func() error) *Handler {
	return &Handler{
		cfg:      cfg,
		cfgPath:  cfgPath,
		certMgr:  certMgr,
		proxies:  proxies,
		onChange: onChange,
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", h.handleDashboard)
	mux.HandleFunc("/proxies", h.handleProxies)
	mux.HandleFunc("/proxies/add", h.handleAddProxy)
	mux.HandleFunc("/proxies/delete", h.handleDeleteProxy)
	mux.HandleFunc("/certs", h.handleCerts)
	mux.HandleFunc("/certs/renew", h.handleRenewCert)
	mux.HandleFunc("/config", h.handleConfig)
	mux.HandleFunc("/config/update", h.handleUpdateConfig)
	mux.HandleFunc("/config/wildcard/add", h.handleAddWildcard)
	mux.HandleFunc("/config/wildcard/delete", h.handleDeleteWildcard)
	mux.HandleFunc("/favicon.ico", h.handleFavicon)
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
	Domain     string
	Status     string
	ExpiryDate string
	DaysLeft   int
	Issuer     string
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
	Wildcards []string
	Certs     []CertInfo
}

func (h *Handler) handleCerts(w http.ResponseWriter, r *http.Request) {
	data := CertsData{
		PageData: PageData{
			ActiveNav: "certs",
			Config:    h.cfg,
		},
		Wildcards: h.cfg.Wildcards,
		Certs:     h.getCertInfo(),
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
		exists := false
		for _, w := range h.cfg.Wildcards {
			if w == wildcard {
				exists = true
				break
			}
		}
		if !exists {
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
		newWildcards := []string{}
		for _, w := range h.cfg.Wildcards {
			if w != wildcard {
				newWildcards = append(newWildcards, w)
			}
		}
		h.cfg.Wildcards = newWildcards
		if err := h.saveAndReload(); err != nil {
			log.Error("Failed to save config", "err", err)
			http.Redirect(w, r, "/config?error=save_failed", http.StatusSeeOther)
			return
		}
	}

	http.Redirect(w, r, "/config", http.StatusSeeOther)
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

	certFile := filepath.Join(h.cfg.CertDir, domain+".crt")
	keyFile := filepath.Join(h.cfg.CertDir, domain+".key")

	if strings.HasPrefix(domain, "*.") {
		baseDomain := domain[2:]
		certFile = filepath.Join(h.cfg.CertDir, baseDomain+".crt")
		keyFile = filepath.Join(h.cfg.CertDir, baseDomain+".key")
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
