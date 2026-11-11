package control

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/abcdlsj/nexo/internal/buildinfo"
	"github.com/abcdlsj/nexo/pkg/cert"
	"github.com/abcdlsj/nexo/pkg/config"
	"github.com/abcdlsj/nexo/pkg/proxy"
	"github.com/abcdlsj/nexo/pkg/traffic"
)

// APIVersion is the wire version of the control API. v1 within this string may
// only gain optional fields; breaking changes move to control.nexo.io/v2.
const APIVersion = "control.nexo.io/v1"

// Envelope is the common response wrapper.
type Envelope struct {
	APIVersion string    `json:"api_version"`
	Kind       string    `json:"kind"`
	Meta       Meta      `json:"meta"`
	Data       any       `json:"data,omitempty"`
	Error      *APIError `json:"error,omitempty"`
}

// Meta identifies one response.
type Meta struct {
	RequestID   string    `json:"request_id"`
	NodeID      string    `json:"node_id,omitempty"`
	ConfigHash  string    `json:"config_hash,omitempty"`
	GeneratedAt time.Time `json:"generated_at"`
	ObservedAt  time.Time `json:"observed_at,omitempty"`
}

// APIError is stable for clients: message is human text, code is the contract.
type APIError struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Retryable bool           `json:"retryable"`
	Details   map[string]any `json:"details,omitempty"`
}

func (e *APIError) Error() string { return e.Code + ": " + e.Message }

// ResourceMeta is shared by every resource.
type ResourceMeta struct {
	ID         string            `json:"id"`
	NodeID     string            `json:"node_id"`
	UpdatedAt  time.Time         `json:"updated_at,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	ConfigHash string            `json:"config_hash,omitempty"`
}

// Node is one Nexo process.
type Node struct {
	Kind     string   `json:"kind"`
	Metadata ResMeta  `json:"metadata"`
	Spec     NodeSpec `json:"spec"`
	Status   NodeStat `json:"status"`
}

type ResMeta struct {
	ID        string `json:"id"`
	NodeID    string `json:"node_id"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type NodeSpec struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Commit  string            `json:"commit"`
	Labels  map[string]string `json:"labels,omitempty"`
}

type NodeStat struct {
	Phase         string `json:"phase"`
	StartedAt     string `json:"started_at"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	ConfigHash    string `json:"config_hash"`
	Listen        string `json:"control_listen,omitempty"`
}

// Route is one host the node serves.
type Route struct {
	Kind     string    `json:"kind"`
	Metadata ResMeta   `json:"metadata"`
	Spec     RouteSpec `json:"spec"`
	Status   RouteStat `json:"status"`
}

type RouteSpec struct {
	RouteID      string         `json:"route_id"`
	Host         string         `json:"host"`
	Kind         string         `json:"route_kind"` // proxy | redirect
	Backend      Backend        `json:"backend"`
	AuthRequired bool           `json:"auth_required"`
	AuthExclude  []string       `json:"auth_exclude,omitempty"`
	Enabled      bool           `json:"enabled"`
	Source       string         `json:"source"` // config | docker
	Portal       *PortalSummary `json:"portal,omitempty"`
}

// Backend deliberately omits paths and credentials: only scheme, host and port
// leave the node.
type Backend struct {
	Kind    string `json:"kind"` // http | redirect | node_route
	Scheme  string `json:"scheme,omitempty"`
	Host    string `json:"host,omitempty"`
	Port    int    `json:"port,omitempty"`
	NodeID  string `json:"node_id,omitempty"`
	RouteID string `json:"route_id,omitempty"`
}

type PortalSummary struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Group       string `json:"group,omitempty"`
	ServiceKind string `json:"service_kind,omitempty"`
	Order       int    `json:"order,omitempty"`
	Hidden      bool   `json:"hidden,omitempty"`
}

type RouteStat struct {
	Healthy   string `json:"healthy"` // healthy | unavailable | unknown
	CheckedAt string `json:"checked_at,omitempty"`
}

// Certificate is read-only certificate state; key material never crosses the API.
type Certificate struct {
	Kind     string   `json:"kind"`
	Metadata ResMeta  `json:"metadata"`
	Spec     CertSpec `json:"spec"`
	Status   CertStat `json:"status"`
}

type CertSpec struct {
	Domain   string `json:"domain"`
	Wildcard bool   `json:"wildcard"`
	Issuer   string `json:"issuer,omitempty"`
}

type CertStat struct {
	State          string `json:"state"` // valid | expiring | expired | missing
	NotAfter       string `json:"not_after,omitempty"`
	DaysLeft       int    `json:"days_left"`
	UsesWildcard   bool   `json:"uses_wildcard,omitempty"`
	WildcardDomain string `json:"wildcard_domain,omitempty"`
}

// Traffic aggregates request telemetry. Recent records are only included when
// explicitly requested and are always redacted.
type Traffic struct {
	Kind     string        `json:"kind"`
	Metadata ResMeta       `json:"metadata"`
	Spec     TrafficSpec   `json:"spec"`
	Status   TrafficStatus `json:"status"`
}

type TrafficSpec struct {
	WindowSeconds int64 `json:"window_seconds"`
	RetentionDays int   `json:"retention_days"`
}

type TrafficStatus struct {
	TotalRequests int64           `json:"total_requests"`
	HTTPSRequests int64           `json:"https_requests"`
	UniqueIPCount int             `json:"unique_ip_count"`
	Domains       []DomainTraffic `json:"domains,omitempty"`
	Recent        []RecentRequest `json:"recent,omitempty"`
	LastSavedAt   string          `json:"last_saved_at,omitempty"`
}

type DomainTraffic struct {
	Domain        string `json:"domain"`
	Requests      int64  `json:"requests"`
	HTTPSRequests int64  `json:"https_requests"`
	UniqueIPCount int    `json:"unique_ip_count"`
}

// RecentRequest is redacted: no raw IP, path or user agent.
type RecentRequest struct {
	Timestamp  string `json:"ts"`
	Domain     string `json:"domain"`
	IPHash     string `json:"ip_hash"`
	Method     string `json:"method"`
	StatusCode int    `json:"status"`
}

// Link is an explicitly declared cross-node relationship.
type Link struct {
	Kind     string   `json:"kind"`
	Metadata ResMeta  `json:"metadata"`
	Spec     LinkSpec `json:"spec"`
	Status   LinkStat `json:"status"`
}

type LinkSpec struct {
	From     LinkEndpoint      `json:"from"`
	To       LinkEndpoint      `json:"to"`
	Relation string            `json:"relation,omitempty"`
	Source   string            `json:"source"` // explicit | inferred | discovered
	Labels   map[string]string `json:"labels,omitempty"`
}

type LinkEndpoint struct {
	NodeID  string `json:"node_id"`
	RouteID string `json:"route_id,omitempty"`
}

type LinkStat struct {
	State string `json:"state"` // connected | unknown_endpoint
}

// Security is the node policy configuration the panel may edit. It carries no
// secrets: blacklist entries are reduced to a count.
type Security struct {
	Kind     string       `json:"kind"`
	Metadata ResMeta      `json:"metadata"`
	Spec     SecuritySpec `json:"spec"`
}

type SecuritySpec struct {
	RateLimitEnabled    bool `json:"rate_limit_enabled"`
	RateLimitRequests   int  `json:"rate_limit_requests"`
	RateLimitWindow     int  `json:"rate_limit_window"`
	MaxLoginAttempts    int  `json:"max_login_attempts"`
	LoginLockoutMinutes int  `json:"login_lockout_minutes"`
	IPBlacklistCount    int  `json:"ip_blacklist_count"`
}

// Snapshot is a consistent view of one node.
type Snapshot struct {
	Node         *Node          `json:"node"`
	Routes       []*Route       `json:"routes"`
	Certificates []*Certificate `json:"certificates"`
	Traffic      *Traffic       `json:"traffic"`
	Security     *Security      `json:"security"`
	Links        []*Link        `json:"links"`
}

// DiscoveredRoute is a route that does not live in the config file (Docker labels).
type DiscoveredRoute struct {
	Upstream  string
	Container string
}

// buildSnapshot assembles the node view. cfg, certDir and traffic may change
// between calls; each call returns a fresh immutable copy.
func buildSnapshot(node nodeInfo, cfg *config.Config, discovered map[string]DiscoveredRoute, trafficMgr *traffic.Manager, recentLimit int) *Snapshot {
	snapshot := &Snapshot{
		Node:         nodeResource(node, cfg),
		Routes:       routesResource(node, cfg, discovered),
		Certificates: certificatesResource(node, cfg),
		Traffic:      trafficResource(node, trafficMgr),
		Security:     securityResource(node, cfg),
		Links:        linksResource(node, cfg),
	}
	if recentLimit > 0 {
		snapshot.Traffic.Status.Recent = recentRecords(node, trafficMgr, recentLimit)
	}
	return snapshot
}

type nodeInfo struct {
	ID      string
	Name    string
	Labels  map[string]string
	Started time.Time
	Listen  string
}

func nodeResource(node nodeInfo, cfg *config.Config) *Node {
	hash := cfg.Hash()
	return &Node{
		Kind:     "Node",
		Metadata: ResMeta{ID: node.ID, NodeID: node.ID, UpdatedAt: node.Started.UTC().Format(time.RFC3339)},
		Spec: NodeSpec{
			ID:      node.ID,
			Name:    node.Name,
			Version: buildVersion(),
			Commit:  buildCommit(),
			Labels:  node.Labels,
		},
		Status: NodeStat{
			Phase:         "running",
			StartedAt:     node.Started.UTC().Format(time.RFC3339),
			UptimeSeconds: int64(time.Since(node.Started).Seconds()),
			ConfigHash:    hash,
			Listen:        node.Listen,
		},
	}
}

func routesResource(node nodeInfo, cfg *config.Config, discovered map[string]DiscoveredRoute) []*Route {
	routes := make([]*Route, 0, len(cfg.Proxies)+len(discovered))
	for host, route := range cfg.Proxies {
		if route == nil {
			continue
		}
		routes = append(routes, routeResource(node, host, route.Upstream, route.Redirect, route.Auth, route.AuthExclude, route.Portal, "config"))
	}
	for host, route := range discovered {
		if route.Upstream == "" {
			continue
		}
		if _, exists := cfg.Proxies[host]; exists {
			continue // static config always wins
		}
		routes = append(routes, routeResource(node, host, route.Upstream, "", false, nil, nil, "docker"))
	}
	sortRoutes(routes)
	return routes
}

func routeResource(node nodeInfo, host, upstream, redirect string, auth bool, authExclude []string, portal *proxy.PortalConfig, source string) *Route {
	spec := RouteSpec{
		RouteID:      host,
		Host:         host,
		Kind:         "proxy",
		AuthRequired: auth,
		AuthExclude:  authExclude,
		Enabled:      true,
		Source:       source,
		Backend:      backendFor(upstream, redirect),
	}
	if redirect != "" {
		spec.Kind = "redirect"
	}
	if portal != nil {
		spec.Portal = &PortalSummary{
			Name:        portal.Name,
			Description: portal.Description,
			Group:       portal.Group,
			ServiceKind: portal.Kind,
			Order:       portal.Order,
			Hidden:      portal.Hidden,
		}
	}
	return &Route{
		Kind:     "Route",
		Metadata: ResMeta{ID: host, NodeID: node.ID},
		Spec:     spec,
		Status:   RouteStat{Healthy: "unknown"},
	}
}

func backendFor(upstream, redirect string) Backend {
	target := upstream
	kind := "http"
	if redirect != "" {
		target = redirect
		kind = "redirect"
	}
	u, err := url.Parse(proxy.EnsureSchema(target))
	if err != nil || u.Host == "" {
		return Backend{Kind: kind}
	}
	port := 0
	if raw := u.Port(); raw != "" {
		port, _ = strconv.Atoi(raw)
	}
	return Backend{Kind: kind, Scheme: u.Scheme, Host: u.Hostname(), Port: port}
}

func securityResource(node nodeInfo, cfg *config.Config) *Security {
	return &Security{
		Kind:     "Security",
		Metadata: ResMeta{ID: "security", NodeID: node.ID},
		Spec: SecuritySpec{
			RateLimitEnabled:    cfg.Security.RateLimitEnabled,
			RateLimitRequests:   cfg.Security.RateLimitRequests,
			RateLimitWindow:     cfg.Security.RateLimitWindow,
			MaxLoginAttempts:    cfg.Security.MaxLoginAttempts,
			LoginLockoutMinutes: cfg.Security.LoginLockoutMinutes,
			IPBlacklistCount:    len(cfg.Security.IPBlacklist),
		},
	}
}

func certificatesResource(node nodeInfo, cfg *config.Config) []*Certificate {
	domains := make([]string, 0, len(cfg.Proxies))
	for host := range cfg.Proxies {
		domains = append(domains, host)
	}
	sort.Strings(domains)
	infos := cert.Inspect(cfg.CertDir, domains, cfg.Wildcards)
	out := make([]*Certificate, 0, len(infos))
	for _, info := range infos {
		state := info.Status
		switch {
		case info.NotAfter.IsZero():
			state = "missing"
		case info.DaysLeft < 0:
			state = "expired"
		case info.DaysLeft < 30:
			state = "expiring"
		default:
			state = "valid"
		}
		status := CertStat{
			State:          state,
			DaysLeft:       info.DaysLeft,
			UsesWildcard:   info.UsesWildcard,
			WildcardDomain: info.WildcardDomain,
		}
		if !info.NotAfter.IsZero() {
			status.NotAfter = info.NotAfter.UTC().Format(time.RFC3339)
		}
		out = append(out, &Certificate{
			Kind:     "Certificate",
			Metadata: ResMeta{ID: info.Domain, NodeID: node.ID},
			Spec: CertSpec{
				Domain:   info.Domain,
				Wildcard: strings.HasPrefix(info.Domain, "*."),
				Issuer:   info.Issuer,
			},
			Status: status,
		})
	}
	return out
}

func trafficResource(node nodeInfo, trafficMgr *traffic.Manager) *Traffic {
	resource := &Traffic{
		Kind:     "TrafficSummary",
		Metadata: ResMeta{ID: "traffic", NodeID: node.ID},
		Spec:     TrafficSpec{RetentionDays: 30},
	}
	if trafficMgr == nil {
		return resource
	}
	data := trafficMgr.GetSummary()
	if data == nil {
		return resource
	}
	resource.Status = TrafficStatus{
		TotalRequests: data.TotalReqs,
		HTTPSRequests: data.HTTPSReqs,
		UniqueIPCount: data.UniqueIPCount,
		LastSavedAt:   data.LastSaved.UTC().Format(time.RFC3339),
	}
	domains := make([]DomainTraffic, 0, len(data.DomainStats))
	for _, stats := range data.DomainStats {
		if stats == nil {
			continue
		}
		domains = append(domains, DomainTraffic{
			Domain:        stats.Domain,
			Requests:      stats.Requests,
			HTTPSRequests: stats.HTTPSCount,
			UniqueIPCount: stats.UniqueIPCount,
		})
	}
	sortDomainTraffic(domains)
	resource.Status.Domains = domains
	if start, end := trafficMgr.TimeRange(); !start.IsZero() {
		resource.Spec.WindowSeconds = int64(end.Sub(start).Seconds())
	}
	return resource
}

func recentRecords(node nodeInfo, trafficMgr *traffic.Manager, limit int) []RecentRequest {
	if trafficMgr == nil {
		return nil
	}
	data := trafficMgr.GetRecentData(limit)
	if data == nil {
		return nil
	}
	if limit > len(data.Records) {
		limit = len(data.Records)
	}
	start := len(data.Records) - limit
	out := make([]RecentRequest, 0, limit)
	for _, record := range data.Records[start:] {
		out = append(out, RecentRequest{
			Timestamp:  record.Timestamp.UTC().Format(time.RFC3339),
			Domain:     record.Domain,
			IPHash:     hashIP(node.ID, record.IP),
			Method:     record.Method,
			StatusCode: record.StatusCode,
		})
	}
	return out
}

func hashIP(nodeID, ip string) string {
	if ip == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(nodeID + "\x00" + ip))
	return hex.EncodeToString(sum[:6])
}

func linksResource(node nodeInfo, cfg *config.Config) []*Link {
	links := cfg.ControlPlane.Topology.Links
	out := make([]*Link, 0, len(links))
	for _, link := range links {
		id := strings.TrimSpace(link.ID)
		if id == "" {
			id = link.From.NodeID + "/" + link.From.RouteID + "->" + link.To.NodeID + "/" + link.To.RouteID
		}
		out = append(out, &Link{
			Kind:     "Link",
			Metadata: ResMeta{ID: id, NodeID: node.ID},
			Spec: LinkSpec{
				From:     LinkEndpoint{NodeID: link.From.NodeID, RouteID: link.From.RouteID},
				To:       LinkEndpoint{NodeID: link.To.NodeID, RouteID: link.To.RouteID},
				Relation: link.Relation,
				Source:   "explicit",
				Labels:   link.Labels,
			},
			Status: LinkStat{State: "unknown_endpoint"},
		})
	}
	return out
}

func buildVersion() string { return buildinfo.Version }
func buildCommit() string  { return buildinfo.Commit }

func sortRoutes(routes []*Route) {
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Spec.Host < routes[j].Spec.Host
	})
}

func sortDomainTraffic(domains []DomainTraffic) {
	sort.Slice(domains, func(i, j int) bool {
		if domains[i].Requests != domains[j].Requests {
			return domains[i].Requests > domains[j].Requests
		}
		return domains[i].Domain < domains[j].Domain
	})
}
