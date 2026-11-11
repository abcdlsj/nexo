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
			Metadata: control.ResMeta{ID: "app.example.com", NodeID: "node-a"},
			Spec: control.RouteSpec{
				RouteID: "app.example.com",
				Host:    "app.example.com",
				Kind:    "proxy",
				Backend: control.Backend{Kind: "http", Scheme: "http", Host: "127.0.0.1", Port: 3000},
				Source:  "config",
			},
		}},
		Certificates: []*control.Certificate{{
			Kind:     "Certificate",
			Metadata: control.ResMeta{ID: "*.example.com", NodeID: "node-a"},
			Spec:     control.CertSpec{Domain: "*.example.com", Wildcard: true},
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
			Metadata: control.ResMeta{ID: "app.example.com", NodeID: "node-b"},
			Spec: control.RouteSpec{
				RouteID: "weft.example.com",
				Host:    "weft.example.com",
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
				From: control.LinkEndpoint{NodeID: "node-a", RouteID: "app.example.com"},
				To:   control.LinkEndpoint{NodeID: "node-b", RouteID: "app.example.com"},
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
	for _, want := range []string{"Gateway A", "Gateway B", "app.example.com", "duplicate_domain", "21 ms", "expiring", `/api/route-icon?domain=app.example.com`, "fleet-leaf-icon"} {
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
	for _, want := range []string{"Gateway A", "app.example.com", "1 nodes"} {
		if !strings.Contains(body, want) {
			t.Fatalf("single-node fleet missing %q", want)
		}
	}
	if strings.Contains(body, "remote-node") {
		t.Fatal("a local-only fleet must not render remote cards")
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
	handler.handleFleetRoute(rec, httptest.NewRequest(http.MethodGet, "/fleet/route?node=node-a&host=app.example.com", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("route form: %d %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "http://127.0.0.1:3000") || !strings.Contains(body, "hash-local") {
		t.Fatal("route form missing prefilled upstream or config hash")
	}

	form := strings.NewReader("node=node-a&host=app.example.com&upstream=http%3A%2F%2F127.0.0.1%3A3001&if_match=hash-local&auth=on")
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
	for _, want := range []string{"*.example.com", "Rate limit requests", "hash-local"} {
		if !strings.Contains(body, want) {
			t.Fatalf("node page missing %q", want)
		}
	}
}
