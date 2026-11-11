package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/abcdlsj/nexo/pkg/config"
	"github.com/charmbracelet/log"
)

const (
	fleetSnapshotLimit = 8 << 20
	defaultPoll        = 10 * time.Second
	defaultTimeout     = 3 * time.Second
	defaultStaleAfter  = 30 * time.Second
)

// Fleet states, in the order a coordinator escalates them.
const (
	StateLocal            = "local"
	StateFresh            = "fresh"
	StateStale            = "stale"
	StateOffline          = "offline"
	StateIdentityMismatch = "identity_mismatch"
	StateMisconfigured    = "misconfigured"
)

// FleetNode is one node in the federated view. Snapshot is nil when the node
// never answered successfully.
type FleetNode struct {
	PeerID        string    `json:"peer_id,omitempty"`
	URL           string    `json:"url,omitempty"`
	State         string    `json:"state"`
	LatencyMS     int64     `json:"latency_ms,omitempty"`
	LastSuccessAt string    `json:"last_success_at,omitempty"`
	LastAttemptAt string    `json:"last_attempt_at,omitempty"`
	Error         *APIError `json:"error,omitempty"`
	Snapshot      *Snapshot `json:"snapshot,omitempty"`
}

// Warning explains why an aggregate cannot be read as a plain sum.
type Warning struct {
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Nodes   []string `json:"nodes,omitempty"`
}

type FleetTotals struct {
	Nodes         int   `json:"nodes"`
	Online        int   `json:"online"`
	Routes        int   `json:"routes"`
	Certificates  int   `json:"certificates"`
	Expiring      int   `json:"expiring"`
	Requests      int64 `json:"requests"`
	HTTPSRequests int64 `json:"https_requests"`
}

// FleetData is the coordinator view. Local always comes first.
type FleetData struct {
	Coordinator bool         `json:"coordinator"`
	GeneratedAt string       `json:"generated_at"`
	Nodes       []*FleetNode `json:"nodes"`
	Links       []*Link      `json:"links"`
	Warnings    []Warning    `json:"warnings,omitempty"`
	Totals      FleetTotals  `json:"totals"`
	Peers       []PeerView   `json:"peers"`
}

// PeerView is the coordinator's own view of a peer, without the snapshot.
type PeerView struct {
	ID            string    `json:"id"`
	Name          string    `json:"name,omitempty"`
	URL           string    `json:"url"`
	State         string    `json:"state"`
	LatencyMS     int64     `json:"latency_ms,omitempty"`
	LastSuccessAt string    `json:"last_success_at,omitempty"`
	Error         *APIError `json:"error,omitempty"`
}

type peerState struct {
	cfg         config.ControlPeerConfig
	snapshot    *Snapshot
	state       string
	lastSuccess time.Time
	lastAttempt time.Time
	latency     time.Duration
	failures    int
	err         *APIError
}

// Federation polls peers concurrently. A slow or dead peer never blocks the
// others and never blocks the data plane.
type Federation struct {
	local func() *Snapshot
	cfg   func() config.CoordinatorConfig

	mu    sync.RWMutex
	peers map[string]*peerState
}

func NewFederation(local func() *Snapshot, cfg func() config.CoordinatorConfig, _ string) *Federation {
	return &Federation{local: local, cfg: cfg, peers: make(map[string]*peerState)}
}

// Run polls until ctx is canceled. Interval changes are picked up on the next
// tick, so a config reload does not need a restart.
func (f *Federation) Run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		cfg := f.cfg()
		if !cfg.Enabled {
			f.reset()
			timer.Reset(5 * time.Second)
			continue
		}

		f.poll(ctx, cfg)
		timer.Reset(parseDuration(cfg.PollInterval, defaultPoll))
	}
}

func (f *Federation) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.peers) > 0 {
		f.peers = make(map[string]*peerState)
	}
}

func (f *Federation) syncPeers(peers []config.ControlPeerConfig) {
	desired := make(map[string]config.ControlPeerConfig, len(peers))
	for _, peer := range peers {
		id := strings.TrimSpace(peer.ID)
		if id == "" {
			log.Warn("Ignoring control peer without id", "url", peer.URL)
			continue
		}
		desired[id] = peer
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	for id, peer := range desired {
		if existing, ok := f.peers[id]; ok {
			existing.cfg = peer
			continue
		}
		f.peers[id] = &peerState{cfg: peer, state: StateOffline}
	}
	for id := range f.peers {
		if _, ok := desired[id]; !ok {
			delete(f.peers, id)
		}
	}
}

func (f *Federation) poll(ctx context.Context, cfg config.CoordinatorConfig) {
	f.syncPeers(cfg.Peers)

	timeout := parseDuration(cfg.RequestTimeout, defaultTimeout)
	client := &http.Client{Timeout: timeout}

	var wg sync.WaitGroup
	for _, peer := range cfg.Peers {
		id := strings.TrimSpace(peer.ID)
		if id == "" {
			continue
		}
		wg.Add(1)
		go func(peer config.ControlPeerConfig) {
			defer wg.Done()
			f.fetch(ctx, client, peer)
		}(peer)
	}
	wg.Wait()
}

func (f *Federation) fetch(ctx context.Context, client *http.Client, peer config.ControlPeerConfig) {
	start := time.Now()

	f.mu.Lock()
	state, ok := f.peers[peer.ID]
	if !ok {
		f.mu.Unlock()
		return
	}
	f.mu.Unlock()

	snapshot, err := fetchPeerSnapshot(ctx, client, peer)
	latency := time.Since(start)

	f.mu.Lock()
	defer f.mu.Unlock()

	state.lastAttempt = time.Now()
	state.latency = latency

	if err != nil {
		state.failures++
		if state.failures >= 3 {
			state.state = StateOffline
		}
		state.err = toAPIError(err)
		return
	}

	if snapshot.Node == nil || snapshot.Node.Spec.ID != peer.ID {
		state.state = StateIdentityMismatch
		state.err = &APIError{
			Code:    "identity_mismatch",
			Message: "peer returned a different node id than configured",
		}
		return
	}

	state.snapshot = snapshot
	state.state = StateFresh
	state.lastSuccess = time.Now()
	state.failures = 0
	state.err = nil
}

func fetchPeerSnapshot(ctx context.Context, client *http.Client, peer config.ControlPeerConfig) (*Snapshot, error) {
	base, err := url.Parse(strings.TrimSpace(peer.URL))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" || base.User != nil {
		return nil, &APIError{Code: "invalid_peer_url", Message: "peer url must be http(s) without credentials"}
	}
	endpoint := strings.TrimRight(base.String(), "/") + "/control/v1/snapshot?recent_limit=0"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	tokenPath := strings.TrimSpace(peer.TokenFile)
	if tokenPath == "" {
		return nil, &APIError{Code: "missing_token", Message: "peer token_file is not configured"}
	}
	token, err := readToken(tokenPath)
	if err != nil {
		return nil, &APIError{Code: "missing_token", Message: "cannot read peer token: " + err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, fleetSnapshotLimit))
	if err != nil {
		return nil, err
	}

	var envelope struct {
		APIVersion string          `json:"api_version"`
		Kind       string          `json:"kind"`
		Data       json.RawMessage `json:"data"`
		Error      *APIError       `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("peer returned invalid JSON (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		if envelope.Error != nil {
			return nil, envelope.Error
		}
		return nil, &APIError{Code: "peer_error", Message: fmt.Sprintf("peer returned status %d", resp.StatusCode)}
	}

	var snapshot Snapshot
	if err := json.Unmarshal(envelope.Data, &snapshot); err != nil {
		return nil, fmt.Errorf("decode peer snapshot: %w", err)
	}
	return &snapshot, nil
}

func toAPIError(err error) *APIError {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return &APIError{Code: "peer_unreachable", Message: err.Error(), Retryable: true}
}

// Snapshot builds the federated view at read time. Staleness is derived from
// the clock, so a peer that stops answering turns stale between polls.
func (f *Federation) Snapshot(local *Snapshot) *FleetData {
	cfg := f.cfg()
	staleAfter := parseDuration(cfg.StaleAfter, defaultStaleAfter)

	data := &FleetData{
		Coordinator: cfg.Enabled,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Nodes:       make([]*FleetNode, 0, len(f.peers)+1),
	}
	if local != nil {
		data.Nodes = append(data.Nodes, &FleetNode{State: StateLocal, Snapshot: local})
	}

	f.mu.RLock()
	peers := make([]*peerState, 0, len(f.peers))
	for _, peer := range f.peers {
		peers = append(peers, peer)
	}
	f.mu.RUnlock()

	sort.Slice(peers, func(i, j int) bool { return peers[i].cfg.ID < peers[j].cfg.ID })

	seenDomains := make(map[string][]string)
	if local != nil {
		for _, route := range local.Routes {
			seenDomains[route.Spec.Host] = append(seenDomains[route.Spec.Host], nodeLabel(local.Node))
		}
	}

	var stalePeers, offlinePeers []string
	for _, peer := range peers {
		state := peer.state
		if state == "" {
			state = StateOffline
		}
		if peer.state != StateIdentityMismatch && peer.state != StateMisconfigured && !peer.lastSuccess.IsZero() {
			if time.Since(peer.lastSuccess) > staleAfter && state == StateFresh {
				state = StateStale
			}
		}

		node := &FleetNode{
			PeerID:    peer.cfg.ID,
			URL:       peer.cfg.URL,
			State:     state,
			LatencyMS: peer.latency.Milliseconds(),
			Error:     peer.err,
		}
		if !peer.lastSuccess.IsZero() {
			node.LastSuccessAt = peer.lastSuccess.UTC().Format(time.RFC3339)
		}
		if !peer.lastAttempt.IsZero() {
			node.LastAttemptAt = peer.lastAttempt.UTC().Format(time.RFC3339)
		}
		if peer.snapshot != nil {
			node.Snapshot = peer.snapshot
			for _, route := range peer.snapshot.Routes {
				seenDomains[route.Spec.Host] = append(seenDomains[route.Spec.Host], nodeLabel(peer.snapshot.Node))
			}
		}
		switch state {
		case StateStale:
			stalePeers = append(stalePeers, peer.cfg.ID)
		case StateOffline:
			offlinePeers = append(offlinePeers, peer.cfg.ID)
		}

		data.Nodes = append(data.Nodes, node)
		data.Peers = append(data.Peers, PeerView{
			ID:            peer.cfg.ID,
			Name:          peer.cfg.Name,
			URL:           peer.cfg.URL,
			State:         state,
			LatencyMS:     peer.latency.Milliseconds(),
			LastSuccessAt: node.LastSuccessAt,
			Error:         peer.err,
		})
	}

	data.Totals.Nodes = len(data.Nodes)
	for _, node := range data.Nodes {
		if node.State == StateLocal || node.State == StateFresh || node.State == StateStale {
			data.Totals.Online++
		}
		if node.Snapshot == nil {
			continue
		}
		data.Totals.Routes += len(node.Snapshot.Routes)
		data.Totals.Certificates += len(node.Snapshot.Certificates)
		for _, certificate := range node.Snapshot.Certificates {
			if certificate.Status.State == "expiring" || certificate.Status.State == "expired" {
				data.Totals.Expiring++
			}
		}
		if node.Snapshot.Traffic != nil {
			data.Totals.Requests += node.Snapshot.Traffic.Status.TotalRequests
			data.Totals.HTTPSRequests += node.Snapshot.Traffic.Status.HTTPSRequests
		}
	}

	data.Links = mergeLinks(data.Nodes)
	data.Warnings = buildWarnings(data, seenDomains, stalePeers, offlinePeers)
	return data
}

func mergeLinks(nodes []*FleetNode) []*Link {
	seen := make(map[string]bool)
	var out []*Link
	byNode := make(map[string]*Snapshot, len(nodes))
	for _, node := range nodes {
		if node.Snapshot == nil {
			continue
		}
		byNode[node.Snapshot.Node.Spec.ID] = node.Snapshot
		for _, link := range node.Snapshot.Links {
			if seen[link.Metadata.ID] {
				continue
			}
			seen[link.Metadata.ID] = true
			copied := *link
			copied.Status = LinkStat{State: linkState(link, byNode)}
			out = append(out, &copied)
		}
	}
	return out
}

func linkState(link *Link, byNode map[string]*Snapshot) string {
	from, ok := byNode[link.Spec.From.NodeID]
	if !ok || !hasRoute(from, link.Spec.From.RouteID) {
		return "unknown_endpoint"
	}
	to, ok := byNode[link.Spec.To.NodeID]
	if !ok || !hasRoute(to, link.Spec.To.RouteID) {
		return "unknown_endpoint"
	}
	return "connected"
}

func hasRoute(snapshot *Snapshot, routeID string) bool {
	if routeID == "" {
		return true
	}
	for _, route := range snapshot.Routes {
		if route.Spec.RouteID == routeID {
			return true
		}
	}
	return false
}

func buildWarnings(data *FleetData, seenDomains map[string][]string, stale, offline []string) []Warning {
	var warnings []Warning
	if len(stale) > 0 {
		warnings = append(warnings, Warning{Code: "stale_peers", Message: "some peers have not reported recently", Nodes: stale})
	}
	if len(offline) > 0 {
		warnings = append(warnings, Warning{Code: "offline_peers", Message: "some peers are offline; totals exclude them", Nodes: offline})
	}

	var duplicates []string
	for host, nodes := range seenDomains {
		if len(nodes) > 1 {
			duplicates = append(duplicates, host+" ("+strings.Join(nodes, ", ")+")")
		}
	}
	if len(duplicates) > 0 {
		sort.Strings(duplicates)
		warnings = append(warnings, Warning{
			Code:    "duplicate_domain",
			Message: "the same host is served by more than one node: " + strings.Join(duplicates, "; "),
		})
	}

	for _, node := range data.Nodes {
		if node.State == StateIdentityMismatch || node.State == StateMisconfigured {
			warnings = append(warnings, Warning{
				Code:    node.State,
				Message: "peer " + node.PeerID + " is not usable: " + errorMessage(node.Error),
				Nodes:   []string{node.PeerID},
			})
		}
	}

	warnings = append(warnings, Warning{
		Code:    "non_additive_metric",
		Message: "unique IP counts are per node; they are not summed across the fleet",
	})
	return warnings
}

func errorMessage(err *APIError) string {
	if err == nil {
		return "unknown error"
	}
	return err.Message
}

func nodeLabel(node *Node) string {
	if node == nil {
		return "unknown"
	}
	if node.Spec.Name != "" {
		return node.Spec.Name
	}
	return node.Spec.ID
}

func parseDuration(raw string, fallback time.Duration) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
