package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
)

const (
	defaultSessionTTL = 24 * time.Hour
	tokenTTL          = 5 * time.Minute
	cookieName        = "nexo_auth"
)

// Config holds the authentication configuration
type Config struct {
	GitHub       GitHubConfig
	AuthHost     string
	SecretKey    string
	SessionTTL   time.Duration
	AllowedHosts []string // allowed redirect hosts (proxy domains)
}

// GitHubConfig holds GitHub OAuth configuration
type GitHubConfig struct {
	ClientID     string
	ClientSecret string
	AllowedUsers []string
}

// Manager handles OAuth authentication
type Manager struct {
	mu     sync.RWMutex
	cfg    Config
	github *GitHubProvider
}

// New creates a new auth manager
func New(cfg Config) *Manager {
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = defaultSessionTTL
	}

	m := &Manager{cfg: cfg}

	if cfg.GitHub.ClientID != "" && cfg.GitHub.ClientSecret != "" {
		m.github = NewGitHubProvider(cfg.GitHub)
	}

	return m
}

// Enabled returns true if authentication is configured
func (m *Manager) Enabled() bool {
	return m.github != nil && m.cfg.AuthHost != ""
}

// UpdateSecretKey updates the secret key used for signing tokens
// This invalidates all existing sessions
func (m *Manager) UpdateSecretKey(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.SecretKey = key
}

// UpdateAllowedHosts updates the allowed redirect hosts list
func (m *Manager) UpdateAllowedHosts(hosts []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.AllowedHosts = hosts
}

// isAllowedHost checks if the host is in the allowed list
func (m *Manager) isAllowedHost(host string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if host == m.cfg.AuthHost {
		return true
	}
	return slices.Contains(m.cfg.AllowedHosts, host)
}

// SessionToken represents a signed session token stored in cookie
type SessionToken struct {
	User      string `json:"user"`
	ExpiresAt int64  `json:"exp"`
}

// TransferToken represents a short-lived token for cross-domain auth transfer
type TransferToken struct {
	User        string `json:"user"`
	RedirectURL string `json:"redirect"`
	ExpiresAt   int64  `json:"exp"`
}

// AuthResult contains the result of authentication check
type AuthResult struct {
	User        string
	NeedRefresh bool
}

// CheckAuth checks if the request is authenticated
// Returns AuthResult with username and whether session needs refresh
func (m *Manager) CheckAuth(r *http.Request) AuthResult {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return AuthResult{}
	}

	token, err := m.parseSessionToken(cookie.Value)
	if err != nil {
		return AuthResult{}
	}

	now := time.Now().Unix()
	if now > token.ExpiresAt {
		return AuthResult{}
	}

	// Check if session needs refresh (less than half TTL remaining)
	remaining := token.ExpiresAt - now
	needRefresh := remaining < int64(m.cfg.SessionTTL.Seconds()/2)

	return AuthResult{User: token.User, NeedRefresh: needRefresh}
}

// RefreshSession refreshes the session cookie if needed
func (m *Manager) RefreshSession(w http.ResponseWriter, user string) {
	m.setSessionCookie(w, user)
}

// IsUserAllowed checks if the user is in the allowed list
func (m *Manager) IsUserAllowed(user string) bool {
	if len(m.cfg.GitHub.AllowedUsers) == 0 {
		return true
	}
	return slices.Contains(m.cfg.GitHub.AllowedUsers, user)
}

// HandleOAuth2 handles all /oauth2/* routes
func (m *Manager) HandleOAuth2(w http.ResponseWriter, r *http.Request, host string) bool {
	switch r.URL.Path {
	case "/oauth2/start":
		m.handleStart(w, r, host)
	case "/oauth2/callback":
		m.handleCallback(w, r)
	case "/oauth2/verify":
		m.handleVerify(w, r)
	case "/oauth2/logout":
		m.handleLogout(w, r)
	default:
		return false
	}
	return true
}

// RedirectToAuth redirects the user to start OAuth flow
func (m *Manager) RedirectToAuth(w http.ResponseWriter, r *http.Request, host string) {
	redirectURL := fmt.Sprintf("https://%s%s", host, r.URL.RequestURI())
	startURL := fmt.Sprintf("https://%s/oauth2/start?redirect=%s",
		m.cfg.AuthHost, url.QueryEscape(redirectURL))
	http.Redirect(w, r, startURL, http.StatusTemporaryRedirect)
}

// handleStart initiates the OAuth flow
func (m *Manager) handleStart(w http.ResponseWriter, r *http.Request, host string) {
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = fmt.Sprintf("https://%s/", host)
	}

	// Validate redirect URL to prevent open redirect
	redirectURL, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "Invalid redirect URL", http.StatusBadRequest)
		return
	}

	// Check if redirect host is allowed
	if !m.isAllowedHost(redirectURL.Host) {
		log.Warn("Redirect to unauthorized host blocked", "host", redirectURL.Host)
		http.Error(w, "Redirect URL not allowed", http.StatusBadRequest)
		return
	}

	// Store redirect in state parameter (signed)
	state := m.createState(redirect)
	callbackURL := fmt.Sprintf("https://%s/oauth2/callback", m.cfg.AuthHost)
	authURL := m.github.AuthURL(state, callbackURL)

	log.Info("Starting OAuth flow", "redirect", redirectURL.Host)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// handleCallback handles the OAuth callback from GitHub
func (m *Manager) handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		http.Error(w, "Missing code parameter", http.StatusBadRequest)
		return
	}

	// Verify and extract redirect URL from state
	redirect, err := m.verifyState(state)
	if err != nil {
		log.Error("Invalid state", "err", err)
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Exchange code for user info
	user, err := m.github.ExchangeCode(r.Context(), code)
	if err != nil {
		log.Error("Failed to exchange code", "err", err)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Check if user is allowed
	if !m.IsUserAllowed(user) {
		log.Warn("User not allowed", "user", user)
		http.Error(w, "Access denied: user not in allowed list", http.StatusForbidden)
		return
	}

	log.Info("User authenticated", "user", user)

	// Parse redirect URL to determine target domain
	redirectURL, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "Invalid redirect URL", http.StatusBadRequest)
		return
	}

	// If redirect is to the auth host itself, set cookie directly
	if redirectURL.Host == m.cfg.AuthHost {
		m.setSessionCookie(w, user)
		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
		return
	}

	// Otherwise, create a transfer token and redirect to target domain
	token := m.createTransferToken(user, redirect)
	verifyURL := fmt.Sprintf("https://%s/oauth2/verify?token=%s",
		redirectURL.Host, url.QueryEscape(token))

	http.Redirect(w, r, verifyURL, http.StatusTemporaryRedirect)
}

// handleVerify verifies the transfer token and sets the session cookie
func (m *Manager) handleVerify(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.URL.Query().Get("token")
	if tokenStr == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	token, err := m.parseTransferToken(tokenStr)
	if err != nil {
		log.Error("Invalid transfer token", "err", err)
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	if time.Now().Unix() > token.ExpiresAt {
		http.Error(w, "Token expired", http.StatusBadRequest)
		return
	}

	// Extract host from redirect URL for cookie domain
	redirectURL, err := url.Parse(token.RedirectURL)
	if err != nil {
		http.Error(w, "Invalid redirect URL", http.StatusBadRequest)
		return
	}

	// Set session cookie for this domain
	m.setSessionCookie(w, token.User)

	log.Info("Session established", "user", token.User, "domain", redirectURL.Host)
	http.Redirect(w, r, token.RedirectURL, http.StatusTemporaryRedirect)
}

// handleLogout clears the session cookie
func (m *Manager) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	} else {
		// Validate redirect URL to prevent open redirect
		if redirectURL, err := url.Parse(redirect); err != nil || !m.isAllowedHost(redirectURL.Host) {
			redirect = "/"
		}
	}

	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}

// setSessionCookie sets the authentication cookie
func (m *Manager) setSessionCookie(w http.ResponseWriter, user string) {
	token := m.createSessionToken(user)

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(m.cfg.SessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// createSessionToken creates a signed session token
func (m *Manager) createSessionToken(user string) string {
	token := SessionToken{
		User:      user,
		ExpiresAt: time.Now().Add(m.cfg.SessionTTL).Unix(),
	}

	data, _ := json.Marshal(token)
	encoded := base64.RawURLEncoding.EncodeToString(data)
	sig := m.sign(encoded)

	return encoded + "." + sig
}

// parseSessionToken parses and verifies a session token
func (m *Manager) parseSessionToken(tokenStr string) (*SessionToken, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	encoded, sig := parts[0], parts[1]

	if !m.verify(encoded, sig) {
		return nil, fmt.Errorf("invalid signature")
	}

	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid encoding: %w", err)
	}

	var token SessionToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("invalid token data: %w", err)
	}

	return &token, nil
}

// createTransferToken creates a short-lived token for cross-domain transfer
func (m *Manager) createTransferToken(user, redirectURL string) string {
	token := TransferToken{
		User:        user,
		RedirectURL: redirectURL,
		ExpiresAt:   time.Now().Add(tokenTTL).Unix(),
	}

	data, _ := json.Marshal(token)
	encoded := base64.RawURLEncoding.EncodeToString(data)
	sig := m.sign(encoded)

	return encoded + "." + sig
}

// parseTransferToken parses and verifies a transfer token
func (m *Manager) parseTransferToken(tokenStr string) (*TransferToken, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	encoded, sig := parts[0], parts[1]

	if !m.verify(encoded, sig) {
		return nil, fmt.Errorf("invalid signature")
	}

	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid encoding: %w", err)
	}

	var token TransferToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("invalid token data: %w", err)
	}

	return &token, nil
}

// createState creates a signed state parameter containing the redirect URL
func (m *Manager) createState(redirectURL string) string {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	data := timestamp + "|" + redirectURL
	encoded := base64.RawURLEncoding.EncodeToString([]byte(data))
	sig := m.sign(encoded)
	return encoded + "." + sig
}

// verifyState verifies the state parameter and extracts the redirect URL
func (m *Manager) verifyState(state string) (string, error) {
	parts := strings.Split(state, ".")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid state format")
	}

	encoded, sig := parts[0], parts[1]

	if !m.verify(encoded, sig) {
		return "", fmt.Errorf("invalid signature")
	}

	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("invalid encoding: %w", err)
	}

	// Parse timestamp|redirect format
	parts = strings.SplitN(string(data), "|", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid state data")
	}

	// Verify timestamp is within 10 minutes
	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid timestamp")
	}

	if time.Now().Unix()-ts > 600 {
		return "", fmt.Errorf("state expired")
	}

	return parts[1], nil
}

// sign creates an HMAC signature
func (m *Manager) sign(data string) string {
	m.mu.RLock()
	key := m.cfg.SecretKey
	m.mu.RUnlock()

	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// verify checks an HMAC signature
func (m *Manager) verify(data, sig string) bool {
	expected := m.sign(data)
	return subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) == 1
}
