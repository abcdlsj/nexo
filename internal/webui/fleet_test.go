package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abcdlsj/nexo/internal/control"
	"github.com/abcdlsj/nexo/pkg/config"
	"github.com/abcdlsj/nexo/pkg/proxy"
)

type fakeFleet struct {
	data    *control.FleetData
	nodeID  string
	command control.CommandRequest
	calls   int
}

func (f *fakeFleet) FleetSnapshot() *control.FleetData { return f.data }

func (f *fakeFleet) FleetCommand(nodeID string, req control.CommandRequest) (*control.CommandResult, error) {
	f.calls++
	f.nodeID = nodeID
	f.command = req
	return &control.CommandResult{Kind: req.Kind, Status: control.CommandSucceeded, NodeID: nodeID}, nil
}

func fleetFixture() *control.FleetData {
	local := &control.Snapshot{
		Node: &control.Node{
			Kind:     "Node",
			Metadata: control.ResMeta{ID: "node-a", NodeID: "node-a"},
			Spec:     control.NodeSpec{ID: "node-a", Name: "Gateway A", Version: "v1.2.3"},
			Status:   control.NodeStat{ConfigHash: "hash-local", UptimeSeconds: 7200},
		},
		Routes: []*control.Route{{
			Kind:     "Route",
			Metadata: control.ResMeta{ID: "app.nexo.local", NodeID: "node-a"},
			Spec: control.RouteSpec{
				RouteID: "app.nexo.local",
				Host:    "app.nexo.local",
				Kind:    "proxy",
				Backend: control.Backend{Kind: "http", Scheme: "http", Host: "127.0.0.1", Port: 3000},
				Source:  "config",
			},
		}},
		Certificates: []*control.Certificate{{
			Kind:     "Certificate",
			Metadata: control.ResMeta{ID: "*.nexo.local", NodeID: "node-a"},
			Spec:     control.CertSpec{Domain: "*.nexo.local", Wildcard: true},
			Status:   control.CertStat{State: "expiring", DaysLeft: 12},
		}},
		Traffic: &control.Traffic{
			Kind: "TrafficSummary",
			Status: control.TrafficStatus{
				TotalRequests: 120, HTTPSRequests: 120, UniqueIPCount: 9,
			},
		},
		Security: &control.Security{
			Kind: "Security",
			Spec: control.SecuritySpec{RateLimitEnabled: true, RateLimitRequests: 100, RateLimitWindow: 60,
				MaxLoginAttempts: 5, LoginLockoutMinutes: 30},
		},
	}

	remote := &control.Snapshot{
		Node: &control.Node{
			Kind:   "Node",
			Spec:   control.NodeSpec{ID: "node-b", Name: "Gateway B", Version: "v1.2.2"},
			Status: control.NodeStat{ConfigHash: "hash-remote", UptimeSeconds: 300},
		},
		Routes: []*control.Route{{
			Kind:     "Route",
			Metadata: control.ResMeta{ID: "app.nexo.local", NodeID: "node-b"},
			Spec: control.RouteSpec{
				RouteID: "weft.nexo.local",
				Host:    "weft.nexo.local",
				Kind:    "proxy",
				Backend: control.Backend{Kind: "http", Scheme: "http", Host: "127.0.0.1", Port: 8899},
			},
		}},
	}

	return &control.FleetData{
		Coordinator: true,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Nodes: []*control.FleetNode{
			{State: control.StateLocal, Snapshot: local},
			{PeerID: "node-b", URL: "http://192.0.2.10:9090", State: control.StateFresh, LatencyMS: 21, Snapshot: remote},
		},
		Links: []*control.Link{{
			Kind:     "Link",
			Metadata: control.ResMeta{ID: "a-to-b"},
			Spec: control.LinkSpec{
				From: control.LinkEndpoint{NodeID: "node-a", RouteID: "app.nexo.local"},
				To:   control.LinkEndpoint{NodeID: "node-b", RouteID: "app.nexo.local"},
			},
			Status: control.LinkStat{State: "connected"},
		}},
		Warnings: []control.Warning{{Code: "duplicate_domain", Message: "the same host is served by more than one node"}},
		Totals:   control.FleetTotals{Nodes: 2, Online: 2, Routes: 2, Certificates: 1, Expiring: 1, Requests: 120, HTTPSRequests: 120},
	}
}

func newFleetHandler(t *testing.T, provider FleetProvider) *Handler {
	t.Helper()
	cfg := &config.Config{
		Proxies: map[string]*proxy.Config{},
		WebUI:   config.WebUIConfig{},
	}
	handler := &Handler{configs: newConfigStore(cfg, "", nil)}
	if provider != nil {
		handler.SetFleet(provider)
	}
	return handler
}

func TestFleetPageRenders(t *testing.T) {
	handler := newFleetHandler(t, &fakeFleet{data: fleetFixture()})
	rec := httptest.NewRecorder()
	handler.handleFleet(rec, httptest.NewRequest(http.MethodGet, "/fleet", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("fleet page: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"Gateway A", "Gateway B", "app.nexo.local", "duplicate_domain", "expiring", `/api/route-icon?domain=app.nexo.local`, "fleet-leaf-icon", "fleet-leaf-open", `href="https://app.nexo.local"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("fleet page missing %q", want)
		}
	}
}

func TestHomeRedirectsToFleet(t *testing.T) {
	handler := newFleetHandler(t, &fakeFleet{data: fleetFixture()})
	rec := httptest.NewRecorder()
	handler.handleHome(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/fleet" {
		t.Fatalf("home: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestFleetPageWithSingleLocalNode(t *testing.T) {
	fixture := fleetFixture()
	data := &control.FleetData{
		GeneratedAt: fixture.GeneratedAt,
		Nodes:       []*control.FleetNode{fixture.Nodes[0]},
		Totals:      control.FleetTotals{Nodes: 1, Online: 1, Routes: 1},
	}
	handler := newFleetHandler(t, &fakeFleet{data: data})
	rec := httptest.NewRecorder()
	handler.handleFleet(rec, httptest.NewRequest(http.MethodGet, "/fleet", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("single-node fleet: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"Gateway A", "app.nexo.local", "1 node"} {
		if !strings.Contains(body, want) {
			t.Fatalf("single-node fleet missing %q", want)
		}
	}
	if strings.Contains(body, "remote-node") {
		t.Fatal("a local-only fleet must not render remote cards")
	}
}

func TestFleetRouteIcons(t *testing.T) {
	snapshot := &control.Snapshot{
		Node: &control.Node{Spec: control.NodeSpec{ID: "node-a", Name: "A"}},
		Routes: []*control.Route{
			{Spec: control.RouteSpec{Host: "a.example.com", Portal: &control.PortalSummary{Icon: "/assets/a.svg"}}},
			{Spec: control.RouteSpec{Host: "b.example.com"}},
			{Spec: control.RouteSpec{Host: "c.example.com", Portal: &control.PortalSummary{Icon: "https://cdn.nexo.local/c.png"}}},
		},
	}
	local := buildNodeView(&control.FleetNode{State: control.StateLocal, Snapshot: snapshot})
	icons := map[string]string{}
	for _, route := range local.Routes {
		icons[route.Host] = route.IconURL
		if route.Initial == "" {
			t.Fatalf("route %s has no placeholder initial", route.Host)
		}
	}
	if icons["a.example.com"] != "/assets/a.svg" {
		t.Fatalf("portal icon not used: %q", icons["a.example.com"])
	}
	if icons["b.example.com"] != "/api/route-icon?domain=b.example.com" {
		t.Fatalf("local fallback icon wrong: %q", icons["b.example.com"])
	}
	if icons["c.example.com"] != "https://cdn.nexo.local/c.png" {
		t.Fatalf("absolute portal icon not used: %q", icons["c.example.com"])
	}

	remote := buildNodeView(&control.FleetNode{State: control.StateFresh, Snapshot: snapshot})
	remoteIcons := map[string]string{}
	for _, route := range remote.Routes {
		remoteIcons[route.Host] = route.IconURL
	}
	if remoteIcons["a.example.com"] != "" {
		t.Fatalf("relative icon must not leak to a peer card: %q", remoteIcons["a.example.com"])
	}
	if remoteIcons["c.example.com"] != "https://cdn.nexo.local/c.png" {
		t.Fatalf("absolute icon should be kept on peers: %q", remoteIcons["c.example.com"])
	}
}

func TestFleetPageWithoutControlPlane(t *testing.T) {
	handler := newFleetHandler(t, nil)
	rec := httptest.NewRecorder()
	handler.handleFleet(rec, httptest.NewRequest(http.MethodGet, "/fleet", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Control plane is disabled") {
		t.Fatalf("expected disabled notice, got %d", rec.Code)
	}
}

func TestFleetRouteFormAndSave(t *testing.T) {
	provider := &fakeFleet{data: fleetFixture()}
	handler := newFleetHandler(t, provider)

	rec := httptest.NewRecorder()
	handler.handleFleetRoute(rec, httptest.NewRequest(http.MethodGet, "/fleet/route?node=node-a&host=app.nexo.local", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("route form: %d %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "http://127.0.0.1:3000") || !strings.Contains(body, "hash-local") {
		t.Fatal("route form missing prefilled upstream or config hash")
	}

	form := strings.NewReader("node=node-a&host=app.nexo.local&upstream=http%3A%2F%2F127.0.0.1%3A3001&if_match=hash-local&auth=on")
	req := httptest.NewRequest(http.MethodPost, "/fleet/route/save", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	handler.handleFleetRouteSave(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save: %d", rec.Code)
	}
	if provider.calls != 1 || provider.nodeID != "node-a" {
		t.Fatalf("command not forwarded: calls=%d node=%q", provider.calls, provider.nodeID)
	}
	if provider.command.Kind != "route.upsert" || provider.command.Route.Upstream != "http://127.0.0.1:3001" || !provider.command.Route.Auth {
		t.Fatalf("unexpected command: %+v", provider.command)
	}
	if provider.command.IfMatch != "hash-local" {
		t.Fatalf("if_match not forwarded: %q", provider.command.IfMatch)
	}
}

func TestFleetNodePageRenders(t *testing.T) {
	handler := newFleetHandler(t, &fakeFleet{data: fleetFixture()})
	rec := httptest.NewRecorder()
	handler.handleFleetNode(rec, httptest.NewRequest(http.MethodGet, "/fleet/node?id=node-a", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("node page: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"*.nexo.local", "Rate limit requests", "hash-local"} {
		if !strings.Contains(body, want) {
			t.Fatalf("node page missing %q", want)
		}
	}
}
