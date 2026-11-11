package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abcdlsj/nexo/pkg/config"
	"github.com/abcdlsj/nexo/pkg/proxy"
	"github.com/abcdlsj/nexo/pkg/traffic"
	"gopkg.in/yaml.v3"
)

// testStore mimics the Web UI config store: one serializer, immutable snapshot.
type testStore struct {
	mu  sync.Mutex
	cfg *config.Config
}

func (s *testStore) get() *config.Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

func (s *testStore) mutate(fn func(*config.Config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := yaml.Marshal(s.cfg)
	if err != nil {
		return err
	}
	var next config.Config
	if err := yaml.Unmarshal(data, &next); err != nil {
		return err
	}
	if err := fn(&next); err != nil {
		return err
	}
	s.cfg = &next
	return nil
}

func newTestServer(t *testing.T, store *testStore, opts ...func(*Options)) (*Server, http.Handler) {
	t.Helper()
	dir := t.TempDir()
	cfg := store.get()
	cfg.BaseDir = dir
	if cfg.CertDir == "" {
		cfg.CertDir = filepath.Join(dir, "certs")
	}
	if cfg.ControlPlane.Listen == "" {
		cfg.ControlPlane.Listen = "127.0.0.1:0"
	}
	if cfg.ControlPlane.Node.ID == "" {
		cfg.ControlPlane.Node.ID = "node-a"
	}
	if cfg.ControlPlane.Node.Name == "" {
		cfg.ControlPlane.Node.Name = "Node A"
	}
	if cfg.ControlPlane.Auth.TokenFile == "" {
		cfg.ControlPlane.Auth.TokenFile = writeToken(t, dir, "read-token")
	}
	if cfg.ControlPlane.Auth.WriteTokenFile == "" {
		cfg.ControlPlane.Auth.WriteTokenFile = writeToken(t, dir, "write-token")
	}

	options := Options{
		Config:    store.get,
		NodeID:    cfg.ControlPlane.Node.ID,
		NodeName:  cfg.ControlPlane.Node.Name,
		StartedAt: time.Now().Add(-time.Hour),
		Listen:    cfg.ControlPlane.Listen,
		BaseDir:   dir,
		Traffic:   nil,
		Mutate:    store.mutate,
	}
	for _, apply := range opts {
		apply(&options)
	}
	ctl, err := New(options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return ctl, ctl.Handler()
}

func writeToken(t *testing.T, dir, token string) string {
	t.Helper()
	path := filepath.Join(dir, "token-"+token)
	if err := os.WriteFile(path, []byte(token+"\n"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	return path
}

func baseConfig() *config.Config {
	timeout := "0"
	return &config.Config{
		Email: "ops@example.com",
		Proxies: map[string]*proxy.Config{
			"app.example.com": {
				Upstream:              "http://127.0.0.1:3000/secret-path",
				Auth:                  true,
				ResponseHeaderTimeout: timeout,
			},
			"old.example.com": {Redirect: "https://example.org"},
		},
		Wildcards: []string{"*.example.com"},
		Cloudflare: config.CloudflareConfig{
			APIToken: "super-secret-token",
		},
		WebUI: config.WebUIConfig{Password: "$2a$10$secret"},
	}
}

func doRequest(t *testing.T, handler http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestNodeIDPersists(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateNodeID(dir)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if len(first) != 32 {
		t.Fatalf("unexpected node id %q", first)
	}
	second, err := LoadOrCreateNodeID(dir)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first != second {
		t.Fatalf("node id changed: %q != %q", first, second)
	}
}

func TestNonLoopbackListenRequiresToken(t *testing.T) {
	cfg := baseConfig()
	cfg.ControlPlane.Listen = "0.0.0.0:9090"
	cfg.BaseDir = t.TempDir()
	_, err := New(Options{Config: func() *config.Config { return cfg }, NodeID: "n", Listen: cfg.ControlPlane.Listen, BaseDir: cfg.BaseDir})
	if err == nil {
		t.Fatal("expected refusal without token")
	}
}

func TestSnapshotAuthAndShape(t *testing.T) {
	store := &testStore{cfg: baseConfig()}
	_, handler := newTestServer(t, store)

	if rec := doRequest(t, handler, http.MethodGet, "/control/v1/snapshot", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous access: got %d", rec.Code)
	}

	rec := doRequest(t, handler, http.MethodGet, "/control/v1/snapshot?include=routes&recent_limit=9999", "read-token", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("snapshot: got %d body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "super-secret-token") || strings.Contains(rec.Body.String(), "secret") {
		t.Fatal("snapshot leaked secrets")
	}

	var envelope struct {
		Data Snapshot `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if envelope.Data.Node != nil {
		t.Fatal("include=routes must not return the node resource")
	}
	if len(envelope.Data.Routes) != 2 {
		t.Fatalf("routes: %+v", envelope.Data.Routes)
	}
	for _, route := range envelope.Data.Routes {
		if route.Spec.Backend.Kind == "http" && route.Spec.Backend.Port != 3000 {
			t.Fatalf("unexpected backend: %+v", route.Spec.Backend)
		}
	}
	if envelope.Data.Traffic != nil {
		t.Fatal("include=routes must not return traffic")
	}
}

func TestSnapshotETagAndHead(t *testing.T) {
	store := &testStore{cfg: baseConfig()}
	_, handler := newTestServer(t, store)

	first := doRequest(t, handler, http.MethodGet, "/control/v1/snapshot", "read-token", "")
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag")
	}

	req := httptest.NewRequest(http.MethodGet, "/control/v1/snapshot", nil)
	req.Header.Set("Authorization", "Bearer read-token")
	req.Header.Set("If-None-Match", etag)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("expected 304, got %d", rec.Code)
	}
}

func TestRecentRecordsAreRedacted(t *testing.T) {
	store := &testStore{cfg: baseConfig()}
	trafficDir := t.TempDir()
	trafficMgr := traffic.NewManager(trafficDir)
	defer trafficMgr.Stop()

	trafficMgr.Record(traffic.RequestRecord{
		Timestamp:  time.Now(),
		Domain:     "app.example.com",
		IP:         "203.0.113.9",
		Method:     http.MethodGet,
		Path:       "/private/account",
		StatusCode: 200,
		IsHTTPS:    true,
		UserAgent:  "curl/8",
	})
	waitFor(t, func() bool { return trafficMgr.GetSummary().TotalReqs == 1 })

	_, handler := newTestServer(t, store, func(o *Options) { o.Traffic = trafficMgr })
	rec := doRequest(t, handler, http.MethodGet, "/control/v1/snapshot?recent_limit=10", "read-token", "")
	body := rec.Body.String()
	for _, forbidden := range []string{"203.0.113.9", "/private/account", "curl/8"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("recent record leaked %q", forbidden)
		}
	}
	if !strings.Contains(body, `"ip_hash"`) {
		t.Fatal("recent record should carry a hashed IP")
	}
}

func TestRouteUpsertIfMatchAndDelete(t *testing.T) {
	store := &testStore{cfg: baseConfig()}
	_, handler := newTestServer(t, store)
	ifMatch := store.get().Hash()

	body := `{"kind":"route.upsert","route_id":"new.example.com","if_match":"` + ifMatch + `","route":{"host":"new.example.com","upstream":"http://127.0.0.1:8080","auth":true}}`
	rec := doRequest(t, handler, http.MethodPost, "/control/v1/commands", "write-token", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("upsert: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := store.get().Proxies["new.example.com"]; !ok {
		t.Fatal("route was not written")
	}

	// Read token must not be accepted for writes.
	rec = doRequest(t, handler, http.MethodPost, "/control/v1/commands", "read-token", body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("read token write: got %d", rec.Code)
	}

	// Stale If-Match is a conflict, and nothing is written.
	stale := `{"kind":"route.upsert","route_id":"stale.example.com","if_match":"` + ifMatch + `","route":{"host":"stale.example.com","upstream":"http://127.0.0.1:8080"}}`
	rec = doRequest(t, handler, http.MethodPost, "/control/v1/commands", "write-token", stale)
	if rec.Code != http.StatusConflict {
		t.Fatalf("conflict: got %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := store.get().Proxies["stale.example.com"]; ok {
		t.Fatal("conflicting write was applied")
	}

	deleteBody := `{"kind":"route.delete","route_id":"app.example.com","if_match":"` + store.get().Hash() + `"}`
	rec = doRequest(t, handler, http.MethodPost, "/control/v1/commands", "write-token", deleteBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := store.get().Proxies["app.example.com"]; ok {
		t.Fatal("route was not deleted")
	}

	auditPath := filepath.Join(store.get().BaseDir, auditFileName)
	if data, err := os.ReadFile(auditPath); err != nil || !strings.Contains(string(data), "route.upsert") {
		t.Fatalf("audit log missing: %v", err)
	}
}

func TestPreserveUpstreamPath(t *testing.T) {
	cases := []struct {
		previous, next, want string
	}{
		{"http://127.0.0.1:9000/gnar", "http://127.0.0.1:9000", "http://127.0.0.1:9000/gnar"},
		{"http://127.0.0.1:9000/gnar", "http://127.0.0.1:9001", "http://127.0.0.1:9001"},
		{"http://127.0.0.1:9000/gnar", "http://127.0.0.1:9000/other", "http://127.0.0.1:9000/other"},
		{"http://127.0.0.1:9000", "http://127.0.0.1:9000", "http://127.0.0.1:9000"},
	}
	for _, test := range cases {
		if got := preserveUpstreamPath(test.previous, test.next); got != test.want {
			t.Errorf("preserveUpstreamPath(%q, %q) = %q, want %q", test.previous, test.next, got, test.want)
		}
	}
}

func TestContainerOwnedRouteIsReadOnly(t *testing.T) {
	store := &testStore{cfg: baseConfig()}
	_, handler := newTestServer(t, store, func(o *Options) {
		o.Discovered = func() map[string]DiscoveredRoute {
			return map[string]DiscoveredRoute{"container.example.com": {Upstream: "http://172.18.0.4:8080", Container: "api"}}
		}
	})

	body := `{"kind":"route.upsert","route_id":"container.example.com","route":{"host":"container.example.com","upstream":"http://127.0.0.1:8080"}}`
	rec := doRequest(t, handler, http.MethodPost, "/control/v1/commands", "write-token", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("container route write: got %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := store.get().Proxies["container.example.com"]; ok {
		t.Fatal("container-owned route was written to the config file")
	}
}

func TestRouteUpsertValidation(t *testing.T) {
	store := &testStore{cfg: baseConfig()}
	_, handler := newTestServer(t, store)

	cases := []string{
		`{"kind":"route.upsert","route_id":"bad","route":{"host":"bad","upstream":"http://127.0.0.1:1"}}`,
		`{"kind":"route.upsert","route_id":"x.example.com","route":{"host":"x.example.com","upstream":"ftp://127.0.0.1:1"}}`,
		`{"kind":"route.upsert","route_id":"x.example.com","route":{"host":"x.example.com","upstream":"http://127.0.0.1:1","redirect":"https://e.com"}}`,
		`{"kind":"route.upsert","route_id":"x.example.com","route":{"host":"x.example.com"}}`,
		`{"kind":"unknown","route_id":"x.example.com"}`,
	}
	for _, body := range cases {
		rec := doRequest(t, handler, http.MethodPost, "/control/v1/commands", "write-token", body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s: got %d", body, rec.Code)
		}
	}
}

func TestCommandForwardingToPeer(t *testing.T) {
	peerStore := &testStore{cfg: baseConfig()}
	_, peerHandler := newTestServer(t, peerStore)
	peer := httptest.NewServer(peerHandler)
	defer peer.Close()

	hubStore := &testStore{cfg: baseConfig()}
	hub, hubHandler := newTestServer(t, hubStore)
	dir := t.TempDir()
	readTokenPath := writeToken(t, dir, "read-token")
	writeTokenPath := writeToken(t, dir, "write-token")

	hub.fed.syncPeers([]config.ControlPeerConfig{{
		ID:             "peer-node",
		URL:            peer.URL,
		TokenFile:      readTokenPath,
		WriteTokenFile: writeTokenPath,
	}})

	body := `{"kind":"route.upsert","target_node_id":"peer-node","route_id":"forwarded.example.com","route":{"host":"forwarded.example.com","upstream":"http://127.0.0.1:8080"}}`
	rec := doRequest(t, hubHandler, http.MethodPost, "/control/v1/commands", "write-token", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("forward: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := peerStore.get().Proxies["forwarded.example.com"]; !ok {
		t.Fatal("peer did not apply the forwarded command")
	}
	if _, ok := hubStore.get().Proxies["forwarded.example.com"]; ok {
		t.Fatal("hub applied a command addressed to a peer")
	}

	// A peer rejection keeps the peer's own status and error code.
	rec = doRequest(t, hubHandler, http.MethodPost, "/control/v1/commands", "write-token",
		`{"kind":"route.upsert","target_node_id":"peer-node","route_id":"forwarded.example.com","if_match":"stale","route":{"host":"forwarded.example.com","upstream":"http://127.0.0.1:8080"}}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("peer conflict was masked: got %d %s", rec.Code, rec.Body.String())
	}
	var conflict struct {
		Data CommandResult `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &conflict); err != nil {
		t.Fatal(err)
	}
	if conflict.Data.Status != CommandConflict {
		t.Fatalf("unexpected forwarded result: %+v", conflict.Data)
	}

	rec = doRequest(t, hubHandler, http.MethodPost, "/control/v1/commands", "write-token",
		`{"kind":"route.upsert","target_node_id":"missing","route_id":"x.example.com","route":{"host":"x.example.com","upstream":"http://127.0.0.1:1"}}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown target: got %d", rec.Code)
	}
}

func TestFederationStates(t *testing.T) {
	store := &testStore{cfg: baseConfig()}
	ctl, server := newTestServer(t, store)
	peer := httptest.NewServer(server)
	defer peer.Close()

	dir := t.TempDir()
	readTokenPath := writeToken(t, dir, "read-token")
	fed := NewFederation(func() *Snapshot { return ctl.Snapshot(0) }, func() config.CoordinatorConfig {
		return config.CoordinatorConfig{
			Enabled:      true,
			PollInterval: "1s",
			StaleAfter:   "2s",
			Peers: []config.ControlPeerConfig{{
				ID:        "node-a",
				URL:       peer.URL,
				TokenFile: readTokenPath,
			}},
		}
	}, ctl.NodeID())

	cfg := fed.cfg()
	fed.poll(context.Background(), cfg)

	data := fed.Snapshot(ctl.Snapshot(0))
	if len(data.Nodes) != 2 {
		t.Fatalf("expected local + peer, got %d", len(data.Nodes))
	}
	var remote *FleetNode
	for _, node := range data.Nodes {
		if node.State != StateLocal {
			remote = node
		}
	}
	if remote == nil || remote.State != StateFresh {
		t.Fatalf("peer state: %+v", remote)
	}

	// Identity mismatch: the configured peer id no longer matches the node id
	// the peer reports.
	mismatchFed := NewFederation(func() *Snapshot { return ctl.Snapshot(0) }, func() config.CoordinatorConfig {
		return config.CoordinatorConfig{Enabled: true, Peers: []config.ControlPeerConfig{{
			ID:        "other-node",
			URL:       peer.URL,
			TokenFile: readTokenPath,
		}}}
	}, ctl.NodeID())
	mismatchFed.poll(context.Background(), mismatchFed.cfg())
	if state := fedSnapshotState(mismatchFed, ctl); state != StateIdentityMismatch {
		t.Fatalf("expected identity_mismatch, got %s", state)
	}
}

func fedSnapshotState(fed *Federation, ctl *Server) string {
	data := fed.Snapshot(ctl.Snapshot(0))
	for _, node := range data.Nodes {
		if node.State != StateLocal {
			return node.State
		}
	}
	return ""
}

func TestFederationDuplicateDomainWarning(t *testing.T) {
	store := &testStore{cfg: baseConfig()}
	ctl, server := newTestServer(t, store)
	peer := httptest.NewServer(server)
	defer peer.Close()

	fed := NewFederation(func() *Snapshot { return ctl.Snapshot(0) }, func() config.CoordinatorConfig {
		return config.CoordinatorConfig{Enabled: true, Peers: []config.ControlPeerConfig{{
			ID:        "node-a",
			URL:       peer.URL,
			TokenFile: writeToken(t, t.TempDir(), "read-token"),
		}}}
	}, ctl.NodeID())

	fed.poll(context.Background(), fed.cfg())
	data := fed.Snapshot(ctl.Snapshot(0))
	found := false
	for _, warning := range data.Warnings {
		if warning.Code == "duplicate_domain" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected duplicate_domain warning, got %+v", data.Warnings)
	}
}

func TestFederationOfflineAfterFailures(t *testing.T) {
	store := &testStore{cfg: baseConfig()}
	ctl, _ := newTestServer(t, store)

	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	fed := NewFederation(func() *Snapshot { return ctl.Snapshot(0) }, func() config.CoordinatorConfig {
		return config.CoordinatorConfig{Enabled: true, Peers: []config.ControlPeerConfig{{
			ID:        "node-a",
			URL:       deadURL,
			TokenFile: writeToken(t, t.TempDir(), "read-token"),
		}}}
	}, ctl.NodeID())

	for i := 0; i < 3; i++ {
		fed.poll(context.Background(), fed.cfg())
	}
	if state := fedSnapshotState(fed, ctl); state != StateOffline {
		t.Fatalf("expected offline, got %s", state)
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}
