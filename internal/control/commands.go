package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/abcdlsj/nexo/pkg/config"
	"github.com/abcdlsj/nexo/pkg/proxy"
	"github.com/charmbracelet/log"
)

// Command statuses.
const (
	CommandSucceeded = "succeeded"
	CommandAccepted  = "accepted"
	CommandFailed    = "failed"
	CommandConflict  = "conflict"
	CommandInvalid   = "invalid"
)

// CommandRequest is the write surface of the control plane. A coordinator
// forwards it verbatim; only the target node applies it.
type CommandRequest struct {
	Kind           string          `json:"kind"`
	RouteID        string          `json:"route_id,omitempty"`
	Route          *RouteChange    `json:"route,omitempty"`
	Security       *SecurityChange `json:"security,omitempty"`
	IfMatch        string          `json:"if_match,omitempty"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
}

// RouteChange is the full desired state of the fields the panel owns. Timeouts,
// cache and retry stay under local control and are preserved on update.
type RouteChange struct {
	Host        string         `json:"host,omitempty"`
	Upstream    string         `json:"upstream,omitempty"`
	Redirect    string         `json:"redirect,omitempty"`
	Auth        bool           `json:"auth"`
	AuthExclude []string       `json:"auth_exclude,omitempty"`
	Portal      *PortalSummary `json:"portal,omitempty"`
}

type SecurityChange struct {
	RateLimitEnabled    *bool `json:"rate_limit_enabled,omitempty"`
	RateLimitRequests   *int  `json:"rate_limit_requests,omitempty"`
	RateLimitWindow     *int  `json:"rate_limit_window,omitempty"`
	MaxLoginAttempts    *int  `json:"max_login_attempts,omitempty"`
	LoginLockoutMinutes *int  `json:"login_lockout_minutes,omitempty"`
}

// CommandResult is returned to the caller and written to the audit log.
type CommandResult struct {
	ID               string    `json:"id"`
	Kind             string    `json:"kind"`
	Status           string    `json:"status"`
	NodeID           string    `json:"node_id"`
	RouteID          string    `json:"route_id,omitempty"`
	ConfigHashBefore string    `json:"config_hash_before,omitempty"`
	ConfigHashAfter  string    `json:"config_hash_after,omitempty"`
	ExecutedAt       string    `json:"executed_at"`
	Error            *APIError `json:"error,omitempty"`
}

var (
	errIfMatch        = errors.New("config hash changed")
	errInvalidCommand = errors.New("invalid command")
	errContainerOwned = errors.New("route is owned by a container label")
)

func (s *Server) handleCommands(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, requestIDFrom(w), &APIError{Code: "method_not_allowed", Message: "use POST"})
		return
	}
	if !s.authorize(r, true) {
		writeError(w, http.StatusUnauthorized, requestIDFrom(w), &APIError{Code: "unauthorized", Message: "a write token is required"})
		return
	}

	var req CommandRequest
	if apiErr := decodeJSON(w, r, &req); apiErr != nil {
		writeError(w, http.StatusBadRequest, requestIDFrom(w), apiErr)
		return
	}

	source := strings.TrimSpace(r.Header.Get("X-Nexo-Node-Id"))
	result := s.applyLocal(req, requestIDFrom(w), source)

	status := http.StatusOK
	switch result.Status {
	case CommandAccepted:
		status = http.StatusAccepted
	case CommandInvalid:
		status = http.StatusBadRequest
	case CommandConflict:
		status = http.StatusConflict
	case CommandFailed:
		status = http.StatusInternalServerError
	}
	if result.Error != nil && result.Status == CommandFailed && result.Error.Code == "mutation_unavailable" {
		status = http.StatusServiceUnavailable
	}

	writeEnvelope(w, status, Envelope{
		APIVersion: APIVersion,
		Kind:       "Command",
		Meta:       Meta{RequestID: requestIDFrom(w), NodeID: s.node.ID, GeneratedAt: time.Now().UTC()},
		Data:       result,
	})
}

// Execute applies a command locally or forwards it to a peer. The Web UI uses
// this so browser requests never hold peer credentials.
func (s *Server) Execute(nodeID string, req CommandRequest) (*CommandResult, error) {
	requestID := newRequestID()
	if nodeID == "" || nodeID == s.node.ID {
		return s.applyLocal(req, requestID, ""), nil
	}

	s.fed.mu.RLock()
	peer, ok := s.fed.peers[nodeID]
	s.fed.mu.RUnlock()
	if !ok {
		return nil, &APIError{Code: "unknown_node", Message: "no peer with id " + nodeID}
	}
	if strings.TrimSpace(peer.cfg.WriteTokenFile) == "" {
		return nil, &APIError{Code: "missing_token", Message: "peer has no write_token_file configured"}
	}

	result, err := s.forwardCommand(peer.cfg, req)
	if err != nil {
		return nil, err
	}

	s.audit.Append(AuditEntry{
		RequestID:    requestID,
		Kind:         req.Kind,
		TargetNodeID: nodeID,
		SourceNodeID: s.node.ID,
		RouteID:      result.RouteID,
		Status:       result.Status,
		HashAfter:    result.ConfigHashAfter,
		Error:        errorMessage(result.Error),
	})
	return result, nil
}

func (s *Server) forwardCommand(peer config.ControlPeerConfig, req CommandRequest) (*CommandResult, error) {
	base, err := url.Parse(strings.TrimSpace(peer.URL))
	if err != nil || base.Host == "" {
		return nil, &APIError{Code: "invalid_peer_url", Message: "peer url is invalid"}
	}
	token, err := readToken(peer.WriteTokenFile)
	if err != nil {
		return nil, &APIError{Code: "missing_token", Message: err.Error()}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(base.String(), "/") + "/control/v1/commands"
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Nexo-Node-Id", s.node.ID)

	resp, err := (&http.Client{Timeout: 110 * time.Second}).Do(httpReq)
	if err != nil {
		return nil, &APIError{Code: "peer_unreachable", Message: err.Error(), Retryable: true}
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Data  json.RawMessage `json:"data"`
		Error *APIError       `json:"error"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, fmt.Errorf("peer returned invalid JSON (status %d)", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		if envelope.Error != nil {
			return nil, envelope.Error
		}
		return nil, &APIError{Code: "peer_error", Message: fmt.Sprintf("peer returned status %d", resp.StatusCode)}
	}
	var result CommandResult
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *Server) applyLocal(req CommandRequest, requestID, sourceNode string) *CommandResult {
	result := &CommandResult{
		ID:         requestID,
		Kind:       req.Kind,
		NodeID:     s.node.ID,
		RouteID:    strings.TrimSpace(req.RouteID),
		ExecutedAt: time.Now().UTC().Format(time.RFC3339),
	}

	if cached, ok := s.idem.get(req.IdempotencyKey); ok && req.IdempotencyKey != "" {
		return cached
	}

	finish := func(status string, err *APIError) *CommandResult {
		result.Status = status
		result.Error = err
		s.idem.put(req.IdempotencyKey, result)
		s.audit.Append(AuditEntry{
			RequestID:    requestID,
			Kind:         req.Kind,
			TargetNodeID: s.node.ID,
			SourceNodeID: sourceNode,
			RouteID:      result.RouteID,
			IfMatch:      req.IfMatch,
			HashBefore:   result.ConfigHashBefore,
			HashAfter:    result.ConfigHashAfter,
			Status:       status,
			Error:        errorMessage(err),
		})
		return result
	}

	if s.opts.Mutate == nil {
		return finish(CommandFailed, &APIError{Code: "mutation_unavailable", Message: "this node cannot apply configuration changes"})
	}

	cfg := s.opts.Config()
	if cfg != nil {
		result.ConfigHashBefore = cfg.Hash()
	}

	switch req.Kind {
	case "route.upsert":
		return s.applyRouteUpsert(req, result, finish)
	case "route.delete":
		return s.applyRouteDelete(req, result, finish)
	case "certificate.renew":
		return s.applyCertRenew(req, result, finish)
	case "security.update":
		return s.applySecurityUpdate(req, result, finish)
	default:
		return finish(CommandInvalid, &APIError{Code: "invalid_command", Message: "unsupported command kind: " + req.Kind})
	}
}

func (s *Server) applyRouteUpsert(req CommandRequest, result *CommandResult, finish func(string, *APIError) *CommandResult) *CommandResult {
	if req.Route == nil {
		return finish(CommandInvalid, &APIError{Code: "invalid_command", Message: "route.upsert requires a route object"})
	}
	change := *req.Route
	host := strings.ToLower(strings.TrimSpace(firstNonEmpty(change.Host, req.RouteID)))
	if !validHost(host) {
		return finish(CommandInvalid, &APIError{Code: "invalid_host", Message: "route host is not a valid domain"})
	}
	result.RouteID = host

	upstream := strings.TrimSpace(change.Upstream)
	redirect := strings.TrimSpace(change.Redirect)
	switch {
	case upstream != "" && redirect != "":
		return finish(CommandInvalid, &APIError{Code: "invalid_route", Message: "set either upstream or redirect, not both"})
	case upstream == "" && redirect == "":
		return finish(CommandInvalid, &APIError{Code: "invalid_route", Message: "set either upstream or redirect"})
	case upstream != "" && !validHTTPURL(upstream):
		return finish(CommandInvalid, &APIError{Code: "invalid_upstream", Message: "upstream must be an http(s) URL"})
	case redirect != "" && !validHTTPURL(proxy.EnsureSchema(redirect)):
		return finish(CommandInvalid, &APIError{Code: "invalid_redirect", Message: "redirect must be an http(s) URL"})
	}
	for _, pattern := range change.AuthExclude {
		if !strings.HasPrefix(pattern, "/") || strings.HasPrefix(pattern, "//") {
			return finish(CommandInvalid, &APIError{Code: "invalid_auth_exclude", Message: "auth_exclude entries must be absolute paths"})
		}
	}

	err := s.opts.Mutate(func(next *config.Config) error {
		if req.IfMatch != "" && next.Hash() != req.IfMatch {
			return errIfMatch
		}
		if s.opts.Discovered != nil {
			if _, discovered := s.opts.Discovered()[host]; discovered {
				if _, configured := next.Proxies[host]; !configured {
					return errContainerOwned
				}
			}
		}
		if next.Proxies == nil {
			next.Proxies = make(map[string]*proxy.Config)
		}
		merged := &proxy.Config{}
		if existing := next.Proxies[host]; existing != nil {
			*merged = *existing
		}
		// The control API never carries upstream paths, so an edit that keeps
		// scheme/host/port must not silently drop an existing path.
		merged.Upstream = preserveUpstreamPath(merged.Upstream, upstream)
		merged.Redirect = redirect
		merged.Auth = change.Auth && upstream != ""
		merged.AuthExclude = change.AuthExclude
		merged.Portal = portalFromSummary(change.Portal)
		next.Proxies[host] = merged
		return nil
	})
	return s.finishMutation(req, result, finish, err)
}

func (s *Server) applyRouteDelete(req CommandRequest, result *CommandResult, finish func(string, *APIError) *CommandResult) *CommandResult {
	host := strings.ToLower(strings.TrimSpace(firstNonEmpty(req.RouteID, routeHost(req.Route))))
	if !validHost(host) {
		return finish(CommandInvalid, &APIError{Code: "invalid_host", Message: "route id must be a domain"})
	}
	result.RouteID = host

	err := s.opts.Mutate(func(next *config.Config) error {
		if req.IfMatch != "" && next.Hash() != req.IfMatch {
			return errIfMatch
		}
		delete(next.Proxies, host)
		return nil
	})
	return s.finishMutation(req, result, finish, err)
}

func (s *Server) applyCertRenew(req CommandRequest, result *CommandResult, finish func(string, *APIError) *CommandResult) *CommandResult {
	domain := strings.ToLower(strings.TrimSpace(firstNonEmpty(req.RouteID, routeHost(req.Route))))
	if domain == "" || (!strings.HasPrefix(domain, "*.") && !validHost(domain)) {
		return finish(CommandInvalid, &APIError{Code: "invalid_domain", Message: "certificate.renew requires a domain"})
	}
	result.RouteID = domain
	if s.opts.RenewCert == nil {
		return finish(CommandFailed, &APIError{Code: "mutation_unavailable", Message: "certificate renewal is not wired"})
	}
	go func() {
		if err := s.opts.RenewCert(domain); err != nil {
			log.Error("Remote certificate renewal failed", "domain", domain, "err", err)
		}
	}()
	return finish(CommandAccepted, nil)
}

func (s *Server) applySecurityUpdate(req CommandRequest, result *CommandResult, finish func(string, *APIError) *CommandResult) *CommandResult {
	if req.Security == nil {
		return finish(CommandInvalid, &APIError{Code: "invalid_command", Message: "security.update requires a security object"})
	}
	change := *req.Security
	err := s.opts.Mutate(func(next *config.Config) error {
		if req.IfMatch != "" && next.Hash() != req.IfMatch {
			return errIfMatch
		}
		if change.RateLimitEnabled != nil {
			next.Security.RateLimitEnabled = *change.RateLimitEnabled
		}
		if change.RateLimitRequests != nil && *change.RateLimitRequests > 0 {
			next.Security.RateLimitRequests = *change.RateLimitRequests
		}
		if change.RateLimitWindow != nil && *change.RateLimitWindow > 0 {
			next.Security.RateLimitWindow = *change.RateLimitWindow
		}
		if change.MaxLoginAttempts != nil && *change.MaxLoginAttempts > 0 {
			next.Security.MaxLoginAttempts = *change.MaxLoginAttempts
		}
		if change.LoginLockoutMinutes != nil && *change.LoginLockoutMinutes > 0 {
			next.Security.LoginLockoutMinutes = *change.LoginLockoutMinutes
		}
		return nil
	})
	return s.finishMutation(req, result, finish, err)
}

func (s *Server) finishMutation(req CommandRequest, result *CommandResult, finish func(string, *APIError) *CommandResult, err error) *CommandResult {
	if errors.Is(err, errContainerOwned) {
		return finish(CommandInvalid, &APIError{Code: "container_owned_route", Message: "this host is published by a container label; change the container instead"})
	}
	if errors.Is(err, errIfMatch) {
		current := ""
		if cfg := s.opts.Config(); cfg != nil {
			current = cfg.Hash()
		}
		return finish(CommandConflict, &APIError{
			Code:    "config_changed",
			Message: "the node configuration changed since it was read; refresh and retry",
			Details: map[string]any{"current_config_hash": current},
		})
	}
	if err != nil {
		return finish(CommandFailed, &APIError{Code: "apply_failed", Message: err.Error()})
	}
	if cfg := s.opts.Config(); cfg != nil {
		result.ConfigHashAfter = cfg.Hash()
	}
	return finish(CommandSucceeded, nil)
}

// preserveUpstreamPath keeps the previous request path when the caller sends the
// same authority without one. A different host or port means a real change and
// the new value wins.
func preserveUpstreamPath(previous, next string) string {
	if previous == "" || next == "" {
		return next
	}
	oldURL, err := url.Parse(proxy.EnsureSchema(previous))
	if err != nil {
		return next
	}
	if oldURL.Path == "" || oldURL.Path == "/" {
		return next
	}
	newURL, err := url.Parse(proxy.EnsureSchema(next))
	if err != nil || newURL.Host != oldURL.Host {
		return next
	}
	if newURL.Path != "" && newURL.Path != "/" {
		return next
	}
	newURL.Path = oldURL.Path
	return newURL.String()
}

func portalFromSummary(portal *PortalSummary) *proxy.PortalConfig {
	if portal == nil {
		return nil
	}
	empty := portal.Name == "" && portal.Description == "" && portal.Group == "" &&
		portal.ServiceKind == "" && portal.Order == 0 && !portal.Hidden
	if empty {
		return nil
	}
	return &proxy.PortalConfig{
		Name:        portal.Name,
		Description: portal.Description,
		Group:       portal.Group,
		Kind:        portal.ServiceKind,
		Order:       portal.Order,
		Hidden:      portal.Hidden,
	}
}

func routeHost(change *RouteChange) string {
	if change == nil {
		return ""
	}
	return change.Host
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func validHTTPURL(raw string) bool {
	u, err := url.ParseRequestURI(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil
}

func validHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || len(host) > 253 || strings.Contains(host, ":") {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}
