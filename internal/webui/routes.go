package webui

import (
	"net/http"
	"strings"
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
