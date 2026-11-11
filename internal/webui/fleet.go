package webui

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/abcdlsj/nexo/internal/control"
	"github.com/abcdlsj/nexo/pkg/config"
	"github.com/charmbracelet/log"
)

// FleetProvider is implemented by the server bridge. The Web UI never talks to
// a peer directly and never holds peer tokens.
type FleetProvider interface {
	FleetSnapshot() *control.FleetData
	FleetCommand(nodeID string, req control.CommandRequest) (*control.CommandResult, error)
}

// SetFleet installs the coordinator view. Without it the Fleet page shows an
// explanation instead of fabricated data.
func (h *Handler) SetFleet(provider FleetProvider) {
	if h == nil {
		return
	}
	h.fleet = provider
}

// UpdateConfig applies a mutation through the single config writer, preserving
// atomic writes, reload and rollback semantics.
func (h *Handler) UpdateConfig(mutate func(cfg *config.Config) error) error {
	return h.configs.Update(mutate)
}

// ---------- view models ----------

type FleetView struct {
	Coordinator bool
	GeneratedAt string
	Totals      control.FleetTotals
	Warnings    []control.Warning
	Links       []FleetLinkView
	Nodes       []FleetNodeView
}

type FleetNodeView struct {
	ID, Name        string
	State           string
	Version, Commit string
	PeerID, URL     string
	Latency         string
	Error           string
	LastSuccess     string
	Uptime          string
	Requests, HTTPS int64
	UniqueIPs       int
	ConfigHash      string
	Routes          []FleetRouteView
	Certificates    []FleetCertView
	CertExpiring    int
	CertMissing     int
}

type FleetRouteView struct {
	Host        string
	Name        string
	Initial     string
	IconURL     string
	Kind        string
	Target      string
	Auth        bool
	Source      string
	CertState   string
	CertDays    int
	CertMissing bool
}

// defaultRouteName derives a readable label from the leftmost host label.
func defaultRouteName(domain string) string {
	label := strings.SplitN(domain, ".", 2)[0]
	words := strings.FieldsFunc(label, func(r rune) bool { return r == '-' || r == '_' })
	for i, word := range words {
		letters := []rune(word)
		if len(letters) > 0 {
			letters[0] = []rune(strings.ToUpper(string(letters[0])))[0]
			words[i] = string(letters)
		}
	}
	if len(words) == 0 {
		return domain
	}
	return strings.Join(words, " ")
}

func routeInitial(name string) string {
	letters := []rune(strings.TrimSpace(name))
	if len(letters) == 0 {
		return "N"
	}
	return strings.ToUpper(string(letters[0]))
}

type FleetCertView struct {
	Domain   string
	State    string
	DaysLeft int
	NotAfter string
	Wildcard bool
}

type FleetLinkView struct {
	ID       string
	From     string
	To       string
	Relation string
	State    string
}

type FleetPageData struct {
	PageData
	View    *FleetView
	Notice  string
	Message string
	Error   string
}

func (h *Handler) fleetSnapshot() *control.FleetData {
	if h == nil || h.fleet == nil {
		return nil
	}
	return h.fleet.FleetSnapshot()
}

func (h *Handler) handleFleet(w http.ResponseWriter, r *http.Request) {
	data := FleetPageData{
		PageData: h.newPageData(r, "fleet"),
		Message:  r.URL.Query().Get("message"),
		Error:    r.URL.Query().Get("error"),
	}
	if fleet := h.fleetSnapshot(); fleet != nil {
		data.View = buildFleetView(fleet)
	} else {
		data.Notice = "Control plane is disabled on this node. Enable control_plane with a coordinator and peers to build a fleet view."
	}

	if err := tmpl.ExecuteTemplate(w, "fleet.html", data); err != nil {
		log.Error("Failed to render fleet", "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

type FleetRouteData struct {
	PageData
	NodeID      string
	NodeName    string
	NodeState   string
	ConfigHash  string
	Host        string
	Upstream    string
	Redirect    string
	Auth        bool
	AuthExclude string
	PortalName  string
	PortalGroup string
	PortalIcon  string
	Error       string
	LocalNode   bool
}

func (h *Handler) handleFleetRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	fleet := h.fleetSnapshot()
	if fleet == nil {
		http.Redirect(w, r, "/fleet", http.StatusSeeOther)
		return
	}

	nodeID := strings.TrimSpace(r.URL.Query().Get("node"))
	host := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("host")))
	node := fleetNodeByID(fleet, nodeID)
	if node == nil || node.Snapshot == nil {
		http.Redirect(w, r, "/fleet?error=node_unavailable", http.StatusSeeOther)
		return
	}

	data := FleetRouteData{
		PageData:   h.newPageData(r, "fleet"),
		NodeID:     node.Snapshot.Node.Spec.ID,
		NodeName:   node.Snapshot.Node.Spec.Name,
		NodeState:  node.State,
		ConfigHash: node.Snapshot.Node.Status.ConfigHash,
		Host:       host,
		Error:      r.URL.Query().Get("error"),
		LocalNode:  node.State == control.StateLocal,
	}

	if host != "" {
		route := fleetRouteByHost(node.Snapshot, host)
		if route == nil {
			http.Redirect(w, r, "/fleet?error=route_not_found", http.StatusSeeOther)
			return
		}
		target := renderBackend(route.Spec.Backend)
		if route.Spec.Kind == "redirect" {
			data.Redirect = target
		} else {
			data.Upstream = target
		}
		data.Auth = route.Spec.AuthRequired
		data.AuthExclude = strings.Join(route.Spec.AuthExclude, ", ")
		if route.Spec.Portal != nil {
			data.PortalName = route.Spec.Portal.Name
			data.PortalGroup = route.Spec.Portal.Group
			data.PortalIcon = route.Spec.Portal.Icon
		}
	}

	if err := tmpl.ExecuteTemplate(w, "fleet_route.html", data); err != nil {
		log.Error("Failed to render fleet route", "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *Handler) handleFleetRouteSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/fleet", http.StatusSeeOther)
		return
	}

	nodeID := strings.TrimSpace(r.FormValue("node"))
	host := strings.ToLower(strings.TrimSpace(r.FormValue("host")))
	back := "/fleet/route?node=" + url.QueryEscape(nodeID) + "&host=" + url.QueryEscape(host)

	command := control.CommandRequest{
		Kind:           "route.upsert",
		RouteID:        host,
		IfMatch:        strings.TrimSpace(r.FormValue("if_match")),
		IdempotencyKey: newCommandKey(),
		Route: &control.RouteChange{
			Host:        host,
			Upstream:    strings.TrimSpace(r.FormValue("upstream")),
			Redirect:    strings.TrimSpace(r.FormValue("redirect")),
			Auth:        r.FormValue("auth") == "on",
			AuthExclude: parseAuthExclude(r.FormValue("auth_exclude")),
			Portal: &control.PortalSummary{
				Name:  strings.TrimSpace(r.FormValue("portal_name")),
				Group: strings.TrimSpace(r.FormValue("portal_group")),
				Icon:  strings.TrimSpace(r.FormValue("portal_icon")),
			},
		},
	}
	h.executeFleetCommand(w, r, nodeID, command, back)
}

func (h *Handler) handleFleetRouteDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/fleet", http.StatusSeeOther)
		return
	}
	nodeID := strings.TrimSpace(r.FormValue("node"))
	host := strings.ToLower(strings.TrimSpace(r.FormValue("host")))
	command := control.CommandRequest{
		Kind:           "route.delete",
		RouteID:        host,
		IfMatch:        strings.TrimSpace(r.FormValue("if_match")),
		IdempotencyKey: newCommandKey(),
	}
	h.executeFleetCommand(w, r, nodeID, command, "/fleet")
}

type FleetNodeData struct {
	PageData
	Node      *FleetNodeView
	Security  *control.SecuritySpec
	Message   string
	Error     string
	LocalNode bool
}

func (h *Handler) handleFleetNode(w http.ResponseWriter, r *http.Request) {
	fleet := h.fleetSnapshot()
	if fleet == nil {
		http.Redirect(w, r, "/fleet", http.StatusSeeOther)
		return
	}
	node := fleetNodeByID(fleet, strings.TrimSpace(r.URL.Query().Get("id")))
	if node == nil || node.Snapshot == nil {
		http.Redirect(w, r, "/fleet?error=node_unavailable", http.StatusSeeOther)
		return
	}

	view := buildNodeView(node)
	data := FleetNodeData{
		PageData:  h.newPageData(r, "fleet"),
		Node:      &view,
		Message:   r.URL.Query().Get("message"),
		Error:     r.URL.Query().Get("error"),
		LocalNode: node.State == control.StateLocal,
	}
	if node.Snapshot.Security != nil {
		data.Security = &node.Snapshot.Security.Spec
	}
	if err := tmpl.ExecuteTemplate(w, "fleet_node.html", data); err != nil {
		log.Error("Failed to render fleet node", "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *Handler) handleFleetCertRenew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/fleet", http.StatusSeeOther)
		return
	}
	nodeID := strings.TrimSpace(r.FormValue("node"))
	domain := strings.ToLower(strings.TrimSpace(r.FormValue("domain")))
	command := control.CommandRequest{
		Kind:           "certificate.renew",
		RouteID:        domain,
		IdempotencyKey: newCommandKey(),
	}
	h.executeFleetCommand(w, r, nodeID, command, "/fleet/node?id="+url.QueryEscape(nodeID))
}

func (h *Handler) handleFleetSecuritySave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/fleet", http.StatusSeeOther)
		return
	}
	nodeID := strings.TrimSpace(r.FormValue("node"))
	change := &control.SecurityChange{}
	if value, ok := formInt(r.FormValue("rate_limit_requests")); ok {
		change.RateLimitRequests = &value
	}
	if value, ok := formInt(r.FormValue("rate_limit_window")); ok {
		change.RateLimitWindow = &value
	}
	if value, ok := formInt(r.FormValue("max_login_attempts")); ok {
		change.MaxLoginAttempts = &value
	}
	if value, ok := formInt(r.FormValue("login_lockout_minutes")); ok {
		change.LoginLockoutMinutes = &value
	}
	enabled := r.FormValue("rate_limit_enabled") == "on"
	change.RateLimitEnabled = &enabled

	command := control.CommandRequest{
		Kind:           "security.update",
		Security:       change,
		IfMatch:        strings.TrimSpace(r.FormValue("if_match")),
		IdempotencyKey: newCommandKey(),
	}
	h.executeFleetCommand(w, r, nodeID, command, "/fleet/node?id="+url.QueryEscape(nodeID))
}

func (h *Handler) executeFleetCommand(w http.ResponseWriter, r *http.Request, nodeID string, command control.CommandRequest, back string) {
	if h.fleet == nil {
		http.Redirect(w, r, "/fleet?error=control_plane_disabled", http.StatusSeeOther)
		return
	}
	result, err := h.fleet.FleetCommand(nodeID, command)
	if err != nil {
		log.Error("Fleet command failed", "node", nodeID, "kind", command.Kind, "err", err)
		http.Redirect(w, r, back+"&error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	switch result.Status {
	case control.CommandSucceeded, control.CommandAccepted:
		http.Redirect(w, r, "/fleet?message="+url.QueryEscape(commandMessage(result)), http.StatusSeeOther)
	case control.CommandConflict:
		http.Redirect(w, r, back+"&error="+url.QueryEscape("Configuration changed on the node; reload and retry."), http.StatusSeeOther)
	default:
		message := "Command failed"
		if result.Error != nil {
			message = result.Error.Message
		}
		http.Redirect(w, r, back+"&error="+url.QueryEscape(message), http.StatusSeeOther)
	}
}

func commandMessage(result *control.CommandResult) string {
	switch result.Kind {
	case "route.upsert":
		return "Route saved on " + result.NodeID
	case "route.delete":
		return "Route removed from " + result.NodeID
	case "certificate.renew":
		return "Certificate renewal started on " + result.NodeID
	case "security.update":
		return "Security settings saved on " + result.NodeID
	}
	return "Command " + result.Status
}

// ---------- builders ----------

func buildFleetView(fleet *control.FleetData) *FleetView {
	view := &FleetView{
		Coordinator: fleet.Coordinator,
		GeneratedAt: fleet.GeneratedAt,
		Totals:      fleet.Totals,
		Warnings:    fleet.Warnings,
	}
	for _, node := range fleet.Nodes {
		view.Nodes = append(view.Nodes, buildNodeView(node))
	}
	for _, link := range fleet.Links {
		view.Links = append(view.Links, FleetLinkView{
			ID:       link.Metadata.ID,
			From:     endpointLabel(fleet, link.Spec.From),
			To:       endpointLabel(fleet, link.Spec.To),
			Relation: link.Spec.Relation,
			State:    link.Status.State,
		})
	}
	return view
}

func buildNodeView(node *control.FleetNode) FleetNodeView {
	view := FleetNodeView{
		State:   node.State,
		PeerID:  node.PeerID,
		URL:     node.URL,
		Uptime:  "—",
		Latency: "—",
	}
	if node.LatencyMS > 0 {
		view.Latency = strconv.FormatInt(node.LatencyMS, 10) + " ms"
	}
	if node.LastSuccessAt != "" {
		view.LastSuccess = node.LastSuccessAt
	}
	if node.Error != nil {
		view.Error = node.Error.Message
	}
	if node.Snapshot == nil || node.Snapshot.Node == nil {
		return view
	}

	snapshot := node.Snapshot
	view.ID = snapshot.Node.Spec.ID
	view.Name = snapshot.Node.Spec.Name
	view.Version = snapshot.Node.Spec.Version
	view.Commit = snapshot.Node.Spec.Commit
	view.Uptime = humanUptime(snapshot.Node.Status.UptimeSeconds)
	view.ConfigHash = snapshot.Node.Status.ConfigHash
	if snapshot.Traffic != nil {
		view.Requests = snapshot.Traffic.Status.TotalRequests
		view.HTTPS = snapshot.Traffic.Status.HTTPSRequests
		view.UniqueIPs = snapshot.Traffic.Status.UniqueIPCount
	}
	for _, certificate := range snapshot.Certificates {
		view.Certificates = append(view.Certificates, FleetCertView{
			Domain:   certificate.Spec.Domain,
			State:    certificate.Status.State,
			DaysLeft: certificate.Status.DaysLeft,
			NotAfter: certificate.Status.NotAfter,
			Wildcard: certificate.Spec.Wildcard,
		})
		switch certificate.Status.State {
		case "expiring", "expired":
			view.CertExpiring++
		case "missing":
			view.CertMissing++
		}
	}
	sort.Slice(view.Certificates, func(i, j int) bool {
		return view.Certificates[i].Domain < view.Certificates[j].Domain
	})

	for _, route := range snapshot.Routes {
		name := defaultRouteName(route.Spec.Host)
		if route.Spec.Portal != nil && strings.TrimSpace(route.Spec.Portal.Name) != "" {
			name = route.Spec.Portal.Name
		}
		routeView := FleetRouteView{
			Host:    route.Spec.Host,
			Name:    name,
			Initial: routeInitial(name),
			Kind:    route.Spec.Kind,
			Target:  renderBackend(route.Spec.Backend),
			Auth:    route.Spec.AuthRequired,
			Source:  route.Spec.Source,
		}
		if route.Spec.Portal != nil && strings.TrimSpace(route.Spec.Portal.Icon) != "" {
			icon := strings.TrimSpace(route.Spec.Portal.Icon)
			usable := validPortalIcon(icon) && !strings.EqualFold(icon, "auto")
			if usable && (node.State == control.StateLocal || strings.HasPrefix(icon, "http://") || strings.HasPrefix(icon, "https://")) {
				routeView.IconURL = icon
			}
		}
		if routeView.IconURL == "" && node.State == control.StateLocal {
			routeView.IconURL = "/api/route-icon?domain=" + url.QueryEscape(route.Spec.Host)
		}
		state, days, missing := certificateFor(route.Spec.Host, snapshot.Certificates)
		routeView.CertState = state
		routeView.CertDays = days
		routeView.CertMissing = missing
		view.Routes = append(view.Routes, routeView)
	}
	return view
}

func certificateFor(host string, certs []*control.Certificate) (state string, days int, missing bool) {
	for _, certificate := range certs {
		if certificate.Spec.Domain == host {
			return certificate.Status.State, certificate.Status.DaysLeft, certificate.Status.State == "missing"
		}
	}
	if parts := strings.SplitN(host, ".", 2); len(parts) == 2 {
		wildcard := "*." + parts[1]
		for _, certificate := range certs {
			if certificate.Spec.Domain == wildcard {
				return certificate.Status.State, certificate.Status.DaysLeft, false
			}
		}
	}
	return "missing", 0, true
}

func endpointLabel(fleet *control.FleetData, endpoint control.LinkEndpoint) string {
	for _, node := range fleet.Nodes {
		if node.Snapshot == nil || node.Snapshot.Node == nil {
			continue
		}
		if node.Snapshot.Node.Spec.ID != endpoint.NodeID {
			continue
		}
		label := node.Snapshot.Node.Spec.Name
		if label == "" {
			label = node.Snapshot.Node.Spec.ID
		}
		if endpoint.RouteID != "" {
			return label + " / " + endpoint.RouteID
		}
		return label
	}
	return endpoint.NodeID
}

func renderBackend(backend control.Backend) string {
	if backend.Kind == "node_route" {
		return backend.NodeID + " / " + backend.RouteID
	}
	if backend.Host == "" {
		return "—"
	}
	target := backend.Host
	if backend.Scheme != "" {
		target = backend.Scheme + "://" + target
	}
	if backend.Port > 0 {
		target += ":" + strconv.Itoa(backend.Port)
	}
	return target
}

func humanUptime(seconds int64) string {
	if seconds <= 0 {
		return "—"
	}
	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, minutes)
	default:
		return fmt.Sprintf("%dm", minutes)
	}
}

func fleetNodeByID(fleet *control.FleetData, id string) *control.FleetNode {
	if fleet == nil || id == "" {
		return nil
	}
	for _, node := range fleet.Nodes {
		if node.Snapshot == nil || node.Snapshot.Node == nil {
			continue
		}
		if node.Snapshot.Node.Spec.ID == id || node.PeerID == id {
			return node
		}
	}
	return nil
}

func fleetRouteByHost(snapshot *control.Snapshot, host string) *control.Route {
	if snapshot == nil {
		return nil
	}
	for _, route := range snapshot.Routes {
		if route.Spec.Host == host {
			return route
		}
	}
	return nil
}

func formInt(raw string) (int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return value, true
}

func newCommandKey() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return hex.EncodeToString(buf)
}
