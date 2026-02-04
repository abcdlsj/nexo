package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	githubAuthorizeURL = "https://github.com/login/oauth/authorize"
	githubTokenURL     = "https://github.com/login/oauth/access_token"
	githubUserURL      = "https://api.github.com/user"
)

// GitHubProvider handles GitHub OAuth flow
type GitHubProvider struct {
	clientID     string
	clientSecret string
	httpClient   *http.Client
}

// NewGitHubProvider creates a new GitHub OAuth provider
func NewGitHubProvider(cfg GitHubConfig) *GitHubProvider {
	return &GitHubProvider{
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// AuthURL returns the GitHub authorization URL
func (p *GitHubProvider) AuthURL(state, redirectURI string) string {
	params := url.Values{
		"client_id":    {p.clientID},
		"redirect_uri": {redirectURI},
		"state":        {state},
		"scope":        {"read:user"},
		"allow_signup": {"false"},
	}
	return githubAuthorizeURL + "?" + params.Encode()
}

// ExchangeCode exchanges the authorization code for user info
func (p *GitHubProvider) ExchangeCode(ctx context.Context, code string) (string, error) {
	// Exchange code for access token
	token, err := p.getAccessToken(ctx, code)
	if err != nil {
		return "", fmt.Errorf("failed to get access token: %w", err)
	}

	// Get user info
	user, err := p.getUserInfo(ctx, token)
	if err != nil {
		return "", fmt.Errorf("failed to get user info: %w", err)
	}

	return user, nil
}

// getAccessToken exchanges the code for an access token
func (p *GitHubProvider) getAccessToken(ctx context.Context, code string) (string, error) {
	data := url.Values{
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
		"code":          {code},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, githubTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	if result.Error != "" {
		return "", fmt.Errorf("github error: %s - %s", result.Error, result.ErrorDesc)
	}

	if result.AccessToken == "" {
		return "", fmt.Errorf("empty access token")
	}

	return result.AccessToken, nil
}

// getUserInfo fetches the user's GitHub username
func (p *GitHubProvider) getUserInfo(ctx context.Context, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubUserURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("github API error: %s - %s", resp.Status, string(body))
	}

	var user struct {
		Login string `json:"login"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", fmt.Errorf("failed to parse user response: %w", err)
	}

	if user.Login == "" {
		return "", fmt.Errorf("empty username")
	}

	return user.Login, nil
}
