package webui

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/abcdlsj/nexo/pkg/config"
	"github.com/abcdlsj/nexo/pkg/proxy"
	"github.com/charmbracelet/log"
)

type CertInfo struct {
	Domain         string
	Status         string
	ExpiryDate     string
	DaysLeft       int
	Issuer         string
	UsesWildcard   bool   // whether using a wildcard certificate
	WildcardDomain string // the wildcard domain used (if any)
}

type ProxiesData struct {
	PageData
	Proxies      map[string]*proxy.Config
	DockerRoutes map[string]DynamicRoute
	CreateEditor RouteEditorData
	EditEditor   *RouteEditorData
	Message      string
	Error        string
}

type RouteEditorData struct {
	ID        string
	CSRFToken string
	Form      RouteFormData
}

type RouteFormData struct {
	Editing           bool
	OriginalDomain    string
	Domain            string
	Type              string
	Upstream          string
	Redirect          string
	Auth              bool
	AuthExclude       string
	PortalName        string
	PortalDescription string
	PortalIcon        string
	PortalKind        string
	PortalGroup       string
	PortalOrder       int
	PortalHidden      bool
}

func newRouteFormData(domain string, cfg *proxy.Config) RouteFormData {
	form := RouteFormData{Type: "proxy"}
	if cfg == nil {
		return form
	}

	form.Editing = true
	form.OriginalDomain = domain
	form.Domain = domain
	form.Upstream = cfg.Upstream
	form.Redirect = cfg.Redirect
	form.Auth = cfg.Auth
	form.AuthExclude = strings.Join(cfg.AuthExclude, ", ")
	if cfg.Upstream == "" && cfg.Redirect != "" {
		form.Type = "redirect"
	}
	if cfg.Portal != nil {
		form.PortalName = cfg.Portal.Name
		form.PortalDescription = cfg.Portal.Description
		form.PortalIcon = cfg.Portal.Icon
		form.PortalKind = strings.ToLower(cfg.Portal.Kind)
		form.PortalGroup = cfg.Portal.Group
		form.PortalOrder = cfg.Portal.Order
		form.PortalHidden = cfg.Portal.Hidden
	}
	return form
}

// handleHome sends the root to the fleet view, the only top-level page.
func (h *Handler) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		h.render404(w)
		return
	}
	http.Redirect(w, r, "/fleet", http.StatusSeeOther)
}

// validPortalIcon accepts "auto", a root-relative path, or an HTTP(S) URL.
func validPortalIcon(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "auto") {
		return true
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return true
	}
	return validHTTPURL(raw)
}

func (h *Handler) handleProxies(w http.ResponseWriter, r *http.Request) {
	cfg := h.config()
	pageData := h.newPageData(r, "proxies")
	csrfToken := pageData.CSRFToken
	var editEditor *RouteEditorData
	if editDomain := strings.TrimSpace(r.URL.Query().Get("edit")); editDomain != "" {
		if route, ok := cfg.Proxies[editDomain]; ok {
			editEditor = &RouteEditorData{ID: "edit-route", CSRFToken: csrfToken, Form: newRouteFormData(editDomain, route)}
		}
	}
	data := ProxiesData{
		PageData:     pageData,
		Proxies:      cfg.Proxies,
		DockerRoutes: h.dynamicRoutes(),
		CreateEditor: RouteEditorData{ID: "create-route", CSRFToken: csrfToken, Form: newRouteFormData("", nil)},
		EditEditor:   editEditor,
		Message:      r.URL.Query().Get("message"),
		Error:        r.URL.Query().Get("error"),
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

	domain, cfg, formError := parseRouteForm(r, nil)
	if formError != "" {
		http.Redirect(w, r, "/proxies?error="+formError, http.StatusSeeOther)
		return
	}
	if _, exists := h.config().Proxies[domain]; exists {
		http.Redirect(w, r, "/proxies?error=domain_exists", http.StatusSeeOther)
		return
	}
	if err := h.replaceProxy("", domain, cfg); err != nil {
		if errors.Is(err, errDomainExists) {
			http.Redirect(w, r, "/proxies?error=domain_exists", http.StatusSeeOther)
			return
		}
		log.Error("Failed to save config", "err", err)
		http.Redirect(w, r, "/proxies?error=save_failed", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/proxies?message=Route+added", http.StatusSeeOther)
}

func (h *Handler) handleUpdateProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/proxies", http.StatusSeeOther)
		return
	}

	originalDomain := strings.TrimSpace(r.FormValue("original_domain"))
	if originalDomain == "" {
		http.Redirect(w, r, "/proxies?error=route_not_found", http.StatusSeeOther)
		return
	}
	formError := ""
	err := h.configs.Update(func(next *config.Config) error {
		current, exists := next.Proxies[originalDomain]
		if !exists {
			return errRouteNotFound
		}
		domain, route, parseError := parseRouteForm(r, current)
		if parseError != "" {
			formError = parseError
			return errInvalidForm
		}
		if domain != originalDomain {
			if _, collision := next.Proxies[domain]; collision {
				return errDomainExists
			}
			delete(next.Proxies, originalDomain)
		}
		next.Proxies[domain] = route
		return nil
	})
	if errors.Is(err, errInvalidForm) {
		http.Redirect(w, r, "/proxies?edit="+url.QueryEscape(originalDomain)+"&error="+formError, http.StatusSeeOther)
		return
	}
	if err != nil {
		if errors.Is(err, errRouteNotFound) {
			http.Redirect(w, r, "/proxies?error=route_not_found", http.StatusSeeOther)
			return
		}
		if errors.Is(err, errDomainExists) {
			http.Redirect(w, r, "/proxies?edit="+url.QueryEscape(originalDomain)+"&error=domain_exists", http.StatusSeeOther)
			return
		}
		log.Error("Failed to update route", "domain", originalDomain, "err", err)
		http.Redirect(w, r, "/proxies?edit="+url.QueryEscape(originalDomain)+"&error=save_failed", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/proxies?message=Route+updated", http.StatusSeeOther)
}

// parseAuthExclude splits a comma separated path list, dropping blanks and duplicates.
func parseAuthExclude(raw string) []string {
	seen := make(map[string]bool)
	paths := make([]string, 0, 4)
	for _, part := range strings.Split(raw, ",") {
		path := strings.TrimSpace(part)
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		paths = append(paths, path)
	}
	return paths
}

// validAuthExclude requires every pattern to be an absolute path.
func validAuthExclude(paths []string) bool {
	for _, path := range paths {
		if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
			return false
		}
	}
	return true
}

func parseRouteForm(r *http.Request, current *proxy.Config) (string, *proxy.Config, string) {
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.FormValue("domain"))), ".")
	if !validDomain(domain, false) {
		return "", nil, "invalid_domain"
	}

	cfg := &proxy.Config{}
	if current != nil {
		*cfg = *current
	}
	cfg.Upstream = ""
	cfg.Redirect = ""
	cfg.Auth = false
	cfg.AuthExclude = parseAuthExclude(r.FormValue("auth_exclude"))
	if !validAuthExclude(cfg.AuthExclude) {
		return "", nil, "invalid_auth_exclude"
	}

	switch r.FormValue("type") {
	case "proxy":
		upstream := strings.TrimSpace(r.FormValue("upstream"))
		if !validHTTPURL(upstream) {
			return "", nil, "invalid_upstream"
		}
		cfg.Upstream = upstream
		cfg.Auth = r.FormValue("auth") == "on"
	case "redirect":
		redirect := strings.TrimSpace(r.FormValue("redirect"))
		if !validHTTPURL(proxy.EnsureSchema(redirect)) {
			return "", nil, "invalid_redirect"
		}
		cfg.Redirect = redirect
	default:
		return "", nil, "invalid_proxy_type"
	}

	portalName := strings.TrimSpace(r.FormValue("portal_name"))
	portalDescription := strings.TrimSpace(r.FormValue("portal_description"))
	portalIcon := strings.TrimSpace(r.FormValue("portal_icon"))
	portalKind := strings.TrimSpace(r.FormValue("portal_kind"))
	portalGroup := strings.TrimSpace(r.FormValue("portal_group"))
	portalOrderRaw := strings.TrimSpace(r.FormValue("portal_order"))
	portalHidden := r.FormValue("portal_hidden") == "on"
	if !validPortalIcon(portalIcon) {
		return "", nil, "invalid_portal_icon"
	}
	if portalKind != "" && normalizeRouteKind(portalKind) == "" {
		return "", nil, "invalid_portal_kind"
	}
	portalOrder := 0
	if portalOrderRaw != "" {
		value, err := strconv.Atoi(portalOrderRaw)
		if err != nil {
			return "", nil, "invalid_portal_order"
		}
		portalOrder = value
	}
	cfg.Portal = nil
	if portalName != "" || portalDescription != "" || portalIcon != "" || portalKind != "" || portalGroup != "" || portalOrder != 0 || portalHidden {
		cfg.Portal = &proxy.PortalConfig{
			Name:        portalName,
			Description: portalDescription,
			Icon:        portalIcon,
			Kind:        normalizeRouteKind(portalKind),
			Group:       portalGroup,
			Order:       portalOrder,
			Hidden:      portalHidden,
		}
	}
	return domain, cfg, ""
}

func (h *Handler) replaceProxy(originalDomain, domain string, cfg *proxy.Config) error {
	return h.configs.Update(func(next *config.Config) error {
		if next.Proxies == nil {
			next.Proxies = make(map[string]*proxy.Config)
		}
		if originalDomain != "" {
			if _, exists := next.Proxies[originalDomain]; !exists {
				return errRouteNotFound
			}
		}
		if domain != originalDomain {
			if _, exists := next.Proxies[domain]; exists {
				return errDomainExists
			}
		}
		if originalDomain != "" {
			delete(next.Proxies, originalDomain)
		}
		next.Proxies[domain] = cfg
		return nil
	})
}

func (h *Handler) handleDeleteProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/proxies", http.StatusSeeOther)
		return
	}

	domain := r.FormValue("domain")
	if domain != "" {
		if err := h.configs.Update(func(next *config.Config) error {
			delete(next.Proxies, domain)
			return nil
		}); err != nil {
			log.Error("Failed to save config", "err", err)
			http.Redirect(w, r, "/proxies?error=save_failed", http.StatusSeeOther)
			return
		}
	}

	http.Redirect(w, r, "/proxies", http.StatusSeeOther)
}
