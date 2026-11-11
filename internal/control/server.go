package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/abcdlsj/nexo/pkg/config"
	"github.com/abcdlsj/nexo/pkg/traffic"
	"github.com/charmbracelet/log"
)

const (
	maxRequestSize    = 64 << 10
	maxResponseSize   = 4 << 20
	maxRecentRecords  = 200
	defaultListenAddr = "127.0.0.1:9090"
	auditFileName     = "control-audit.jsonl"
)

// Options wires the control plane to the running server. Every callback is
// evaluated at request time so config reloads take effect without a restart.
type Options struct {
	Config     func() *config.Config
	NodeID     string
	NodeName   string
	Labels     map[string]string
	StartedAt  time.Time
	Listen     string
	BaseDir    string
	Discovered func() map[string]DiscoveredRoute
	Traffic    *traffic.Manager
	Mutate     func(func(*config.Config) error) error
	RenewCert  func(string) error
}

// Server implements the node control API. It never touches data-plane routing
// except through Mutate, which is the same serialized writer the Web UI uses.
type Server struct {
	opts    Options
	node    nodeInfo
	audit   *AuditLog
	fed     *Federation
	idem    *idempotencyCache
	httpSrv *http.Server
	handler http.Handler

	tlsConfig *tls.Config
	lnMu      sync.Mutex
	listener  net.Listener
}

// New validates the security posture and prepares the node identity. It does
// not open a listener; call Start for that.
func New(opts Options) (*Server, error) {
	listen := strings.TrimSpace(opts.Listen)
	if listen == "" {
		listen = defaultListenAddr
	}

	cfg := opts.Config()
	if cfg == nil {
		return nil, errors.New("control plane needs a configuration snapshot")
	}

	nodeID := strings.TrimSpace(opts.NodeID)
	if nodeID == "" {
		var err error
		nodeID, err = LoadOrCreateNodeID(opts.BaseDir)
		if err != nil {
			return nil, err
		}
	}
	nodeName := strings.TrimSpace(opts.NodeName)
	if nodeName == "" {
		nodeName, _ = os.Hostname()
	}
	if nodeName == "" {
		nodeName = nodeID
	}

	if cfg.ControlPlane.Coordinator.Enabled && !cfg.ControlPlane.Enabled {
		log.Warn("Coordinator is enabled but the control plane is disabled; coordinator is idle")
	}

	tlsConfig, err := listenerTLS(cfg.ControlPlane.TLS)
	if err != nil {
		return nil, err
	}
	if err := validateListen(listen, tlsConfig, cfg.ControlPlane.Auth); err != nil {
		return nil, err
	}
	// A token file that is readable by others is a credential leak regardless of
	// where the listener binds, so reject it at startup instead of returning 401
	// on every request.
	for _, tokenFile := range []string{cfg.ControlPlane.Auth.TokenFile, cfg.ControlPlane.Auth.WriteTokenFile} {
		if strings.TrimSpace(tokenFile) != "" {
			if err := requirePrivateFile(tokenFile); err != nil {
				return nil, err
			}
		}
	}

	s := &Server{
		opts: opts,
		node: nodeInfo{
			ID:      nodeID,
			Name:    nodeName,
			Labels:  opts.Labels,
			Started: opts.StartedAt,
			Listen:  listen,
		},
		audit:     NewAuditLog(opts.BaseDir),
		idem:      newIdempotencyCache(15 * time.Minute),
		tlsConfig: tlsConfig,
	}
	s.handler = s.routes()
	s.fed = NewFederation(func() *Snapshot { return s.Snapshot(0) }, func() config.CoordinatorConfig {
		if cfg := s.opts.Config(); cfg != nil {
			return cfg.ControlPlane.Coordinator
		}
		return config.CoordinatorConfig{}
	}, nodeID)

	return s, nil
}

// LoadOrCreateNodeID returns the persisted logical identity, creating it on
// first start. Identity must survive IP changes, so it is never derived from
// the network.
func LoadOrCreateNodeID(baseDir string) (string, error) {
	if strings.TrimSpace(baseDir) == "" {
		return "", errors.New("base_dir is required to persist the control plane node id")
	}
	path := filepath.Join(baseDir, "node-id")
	if data, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(data)); id != "" {
			return id, nil
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("read node id: %w", err)
	}

	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate node id: %w", err)
	}
	id := hex.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(id+"\n"), 0600); err != nil {
		return "", fmt.Errorf("persist node id: %w", err)
	}
	log.Info("Generated control plane node identity", "id", id, "path", path)
	return id, nil
}

func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Start serves the control API until ctx is canceled.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.node.Listen)
	if err != nil {
		return fmt.Errorf("control plane listen: %w", err)
	}
	if s.tlsConfig != nil {
		ln = tls.NewListener(ln, s.tlsConfig)
	}

	s.lnMu.Lock()
	s.listener = ln
	s.lnMu.Unlock()

	s.httpSrv = &http.Server{
		Handler:           s.handler,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		// A route command can wait on ACME issuance, so the write window is
		// wider than a snapshot poll.
		WriteTimeout:   120 * time.Second,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 32 << 10,
	}

	scheme := "http"
	if s.tlsConfig != nil {
		scheme = "https"
	}
	log.Info("Control API listening", "addr", s.node.Listen, "scheme", scheme, "node", s.node.ID)

	go s.fed.Run(ctx)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpSrv.Shutdown(shutdownCtx); err != nil {
			log.Warn("Control API shutdown", "err", err)
		}
	}()

	if err := s.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Handler exposes the HTTP handler for tests.
func (s *Server) Handler() http.Handler { return s.handler }

// Addr returns the bound control address, ready for tests that need port 0.
func (s *Server) Addr() string {
	s.lnMu.Lock()
	defer s.lnMu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// NodeID is the stable identity reported to coordinators.
func (s *Server) NodeID() string { return s.node.ID }

// Snapshot returns the current node view.
func (s *Server) Snapshot(recentLimit int) *Snapshot {
	cfg := s.opts.Config()
	if cfg == nil {
		cfg = &config.Config{}
	}
	discovered := map[string]DiscoveredRoute(nil)
	if s.opts.Discovered != nil {
		discovered = s.opts.Discovered()
	}
	return buildSnapshot(s.node, cfg, discovered, s.opts.Traffic, recentLimit)
}

// FleetSnapshot returns the coordinator view. It is safe to call when the
// coordinator is disabled: the local node is still included.
func (s *Server) FleetSnapshot() *FleetData {
	return s.fed.Snapshot(s.Snapshot(0))
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/control/v1/healthz", s.handleHealthz)
	mux.HandleFunc("/control/v1/node", s.handleNode)
	mux.HandleFunc("/control/v1/capabilities", s.handleCapabilities)
	mux.HandleFunc("/control/v1/snapshot", s.handleSnapshot)
	mux.HandleFunc("/control/v1/resources/", s.handleResources)
	mux.HandleFunc("/control/v1/fleet/snapshot", s.handleFleetSnapshot)
	mux.HandleFunc("/control/v1/commands", s.handleCommands)
	return s.withMiddleware(mux)
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := newRequestID()
		w.Header().Set("X-Request-Id", requestID)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
			w.Header().Set("Allow", "GET, HEAD, POST")
			writeError(w, http.StatusMethodNotAllowed, requestID, &APIError{Code: "method_not_allowed", Message: "unsupported method"})
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, requestIDFrom(w), &APIError{Code: "method_not_allowed", Message: "unsupported method"})
		return
	}
	writeEnvelope(w, http.StatusOK, Envelope{
		APIVersion: APIVersion,
		Kind:       "Health",
		Meta:       Meta{RequestID: requestIDFrom(w), NodeID: s.node.ID, GeneratedAt: time.Now().UTC(), ObservedAt: time.Now().UTC()},
		Data:       map[string]string{"status": "ok"},
	})
}

func (s *Server) handleNode(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(r, false) {
		writeError(w, http.StatusUnauthorized, requestIDFrom(w), unauthorizedError())
		return
	}
	snapshot := s.Snapshot(0)
	writeEnvelope(w, http.StatusOK, Envelope{
		APIVersion: APIVersion,
		Kind:       "Node",
		Meta:       Meta{RequestID: requestIDFrom(w), NodeID: s.node.ID, ConfigHash: snapshot.Node.Status.ConfigHash, GeneratedAt: time.Now().UTC(), ObservedAt: time.Now().UTC()},
		Data:       snapshot.Node,
	})
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(r, false) {
		writeError(w, http.StatusUnauthorized, requestIDFrom(w), unauthorizedError())
		return
	}
	writeEnvelope(w, http.StatusOK, Envelope{
		APIVersion: APIVersion,
		Kind:       "Capabilities",
		Meta:       Meta{RequestID: requestIDFrom(w), NodeID: s.node.ID, GeneratedAt: time.Now().UTC(), ObservedAt: time.Now().UTC()},
		Data: map[string]any{
			"resources": []string{"Node", "Route", "Certificate", "TrafficSummary", "Security", "Link"},
			"features":  []string{"etag", "redacted_traffic", "fleet_snapshot", "commands"},
			"limits":    map[string]int{"max_recent_limit": maxRecentRecords},
			"commands":  []string{"route.upsert", "route.delete", "certificate.renew", "security.update"},
		},
	})
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(r, false) {
		writeError(w, http.StatusUnauthorized, requestIDFrom(w), unauthorizedError())
		return
	}

	include, err := parseInclude(r.URL.Query().Get("include"))
	if err != nil {
		writeError(w, http.StatusBadRequest, requestIDFrom(w), err)
		return
	}
	recent := parseRecent(r.URL.Query().Get("recent_limit"))
	snapshot := s.Snapshot(recent)

	data := snapshot
	if include != nil {
		data = filterSnapshot(snapshot, include)
	}

	s.writeSnapshot(w, r, "Snapshot", data)
}

func (s *Server) handleResources(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(r, false) {
		writeError(w, http.StatusUnauthorized, requestIDFrom(w), unauthorizedError())
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/control/v1/resources/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusNotFound, requestIDFrom(w), &APIError{Code: "not_found", Message: "unknown resource"})
		return
	}

	kind := strings.ToLower(parts[0])
	recent := parseRecent(r.URL.Query().Get("recent_limit"))
	snapshot := s.Snapshot(recent)

	var items any
	switch kind {
	case "node", "nodes":
		items = snapshot.Node
	case "route", "routes":
		items = snapshot.Routes
	case "certificate", "certificates":
		items = snapshot.Certificates
	case "traffic", "trafficsummary":
		items = snapshot.Traffic
	case "security":
		items = snapshot.Security
	case "link", "links":
		items = snapshot.Links
	default:
		writeError(w, http.StatusNotFound, requestIDFrom(w), &APIError{Code: "not_found", Message: "unknown resource kind: " + parts[0]})
		return
	}

	if len(parts) > 1 && parts[1] != "" {
		id := parts[1]
		filtered, ok := filterResourceByID(items, id)
		if !ok {
			writeError(w, http.StatusNotFound, requestIDFrom(w), &APIError{Code: "not_found", Message: "unknown resource id: " + id})
			return
		}
		items = filtered
	}

	s.writeSnapshot(w, r, "ResourceList", items)
}

func (s *Server) handleFleetSnapshot(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(r, false) {
		writeError(w, http.StatusUnauthorized, requestIDFrom(w), unauthorizedError())
		return
	}
	if cfg := s.opts.Config(); cfg == nil || !cfg.ControlPlane.Coordinator.Enabled {
		writeError(w, http.StatusNotFound, requestIDFrom(w), &APIError{Code: "coordinator_disabled", Message: "this node is not a coordinator"})
		return
	}
	s.writeSnapshot(w, r, "FleetSnapshot", s.FleetSnapshot())
}

func (s *Server) writeSnapshot(w http.ResponseWriter, r *http.Request, kind string, data any) {
	// The ETag covers only the payload, not the request id or timestamps, so a
	// poll on an unchanged node returns 304 instead of a full body. Volatile
	// fields (uptime) are normalized so a cache hit stays possible.
	payload, err := json.Marshal(etagView(data))
	if err != nil {
		writeError(w, http.StatusInternalServerError, requestIDFrom(w), &APIError{Code: "encode_failed", Message: "failed to encode response"})
		return
	}
	sum := sha256.Sum256(payload)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	w.Header().Set("ETag", etag)
	if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	envelope := Envelope{
		APIVersion: APIVersion,
		Kind:       kind,
		Meta: Meta{
			RequestID:   requestIDFrom(w),
			NodeID:      s.node.ID,
			ConfigHash:  s.currentHash(),
			GeneratedAt: time.Now().UTC(),
			ObservedAt:  time.Now().UTC(),
		},
		Data: data,
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		writeError(w, http.StatusInternalServerError, requestIDFrom(w), &APIError{Code: "encode_failed", Message: "failed to encode response"})
		return
	}
	if len(body) > maxResponseSize {
		writeError(w, http.StatusRequestEntityTooLarge, requestIDFrom(w), &APIError{Code: "response_too_large", Message: "snapshot exceeds the response limit; lower lower recent_limit"})
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

// etagView zeroes fields that change on every request without changing meaning.
func etagView(data any) any {
	snapshot, ok := data.(*Snapshot)
	if !ok || snapshot == nil || snapshot.Node == nil {
		return data
	}
	clone := *snapshot
	node := *snapshot.Node
	node.Status.UptimeSeconds = 0
	clone.Node = &node
	return &clone
}

func (s *Server) currentHash() string {
	cfg := s.opts.Config()
	if cfg == nil {
		return ""
	}
	return cfg.Hash()
}

// authorize validates the bearer token. Read and write tokens are distinct so
// a monitoring credential cannot mutate configuration.
func (s *Server) authorize(r *http.Request, write bool) bool {
	cfg := s.opts.Config()
	if cfg == nil {
		return false
	}
	auth := cfg.ControlPlane.Auth
	tokenFile := strings.TrimSpace(auth.TokenFile)
	if write {
		tokenFile = strings.TrimSpace(auth.WriteTokenFile)
	}
	if tokenFile == "" {
		// Loopback-only control planes may run tokenless; anything else was
		// rejected at startup.
		return isLoopbackListen(s.node.Listen)
	}

	token := bearerToken(r)
	if token == "" {
		return false
	}
	expected, err := readToken(tokenFile)
	if err != nil {
		log.Warn("Control token unavailable", "file", tokenFile, "err", err)
		return false
	}
	return constantTimeEqual(token, expected)
}

func bearerToken(r *http.Request) string {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	const prefix = "bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

func readToken(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("token file %s must be mode 0600", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func constantTimeEqual(a, b string) bool {
	ah := sha256.Sum256([]byte(a))
	bh := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ah[:], bh[:]) == 1
}

func parseInclude(raw string) (map[string]bool, *APIError) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	known := map[string]bool{
		"node": true, "routes": true, "certificates": true, "traffic": true, "security": true, "links": true,
	}
	set := make(map[string]bool, len(known))
	for _, part := range strings.Split(raw, ",") {
		value := strings.ToLower(strings.TrimSpace(part))
		if value == "" {
			continue
		}
		if !known[value] {
			return nil, &APIError{Code: "invalid_request", Message: "unsupported include value: " + value}
		}
		set[value] = true
	}
	if len(set) == 0 {
		return nil, nil
	}
	return set, nil
}

func filterSnapshot(snapshot *Snapshot, include map[string]bool) *Snapshot {
	out := &Snapshot{}
	if include["node"] {
		out.Node = snapshot.Node
	}
	if include["routes"] {
		out.Routes = snapshot.Routes
	}
	if include["certificates"] {
		out.Certificates = snapshot.Certificates
	}
	if include["traffic"] {
		out.Traffic = snapshot.Traffic
	}
	if include["security"] {
		out.Security = snapshot.Security
	}
	if include["links"] {
		out.Links = snapshot.Links
	}
	return out
}

func filterResourceByID(items any, id string) (any, bool) {
	switch list := items.(type) {
	case []*Route:
		for _, item := range list {
			if item.Metadata.ID == id {
				return item, true
			}
		}
	case []*Certificate:
		for _, item := range list {
			if item.Metadata.ID == id {
				return item, true
			}
		}
	case []*Link:
		for _, item := range list {
			if item.Metadata.ID == id {
				return item, true
			}
		}
	case *Node:
		if list != nil && list.Metadata.ID == id {
			return list, true
		}
	}
	return nil, false
}

func parseRecent(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return 0
	}
	if value > maxRecentRecords {
		return maxRecentRecords
	}
	return value
}

func unauthorizedError() *APIError {
	return &APIError{Code: "unauthorized", Message: "a valid bearer token is required"}
}

func writeEnvelope(w http.ResponseWriter, status int, envelope Envelope) {
	body, err := json.Marshal(envelope)
	if err != nil {
		http.Error(w, `{"api_version":"`+APIVersion+`","kind":"Error","error":{"code":"encode_failed"}}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeError(w http.ResponseWriter, status int, requestID string, apiErr *APIError) {
	writeEnvelope(w, status, Envelope{
		APIVersion: APIVersion,
		Kind:       "Error",
		Meta:       Meta{RequestID: requestID, GeneratedAt: time.Now().UTC()},
		Error:      apiErr,
	})
}

type requestIDKey struct{}

func requestIDFrom(w http.ResponseWriter) string {
	return w.Header().Get("X-Request-Id")
}

func newRequestID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(buf)
}

// decodeJSON reads one bounded JSON body and rejects unknown fields so a typo
// fails loudly instead of being silently ignored.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) *APIError {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		var maxBytes *http.MaxBytesError
		if errors.As(err, &maxBytes) {
			return &APIError{Code: "invalid_request", Message: "request body too large"}
		}
		if errors.Is(err, io.EOF) {
			return &APIError{Code: "invalid_request", Message: "request body is required"}
		}
		return &APIError{Code: "invalid_request", Message: "invalid JSON: " + err.Error()}
	}
	if decoder.More() {
		return &APIError{Code: "invalid_request", Message: "request body must contain a single JSON object"}
	}
	return nil
}

// idempotencyCache remembers command results so a retried request cannot apply
// the same mutation twice.
type idempotencyCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]idempotentEntry
}

type idempotentEntry struct {
	result  *CommandResult
	expires time.Time
}

func newIdempotencyCache(ttl time.Duration) *idempotencyCache {
	return &idempotencyCache{ttl: ttl, entries: make(map[string]idempotentEntry)}
}

func (c *idempotencyCache) get(key string) (*CommandResult, bool) {
	if key == "" {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expires) {
		if ok {
			delete(c.entries, key)
		}
		return nil, false
	}
	return entry.result, true
}

func (c *idempotencyCache) put(key string, result *CommandResult) {
	if key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) > 512 {
		for k, entry := range c.entries {
			if time.Now().After(entry.expires) {
				delete(c.entries, k)
			}
		}
	}
	c.entries[key] = idempotentEntry{result: result, expires: time.Now().Add(c.ttl)}
}
