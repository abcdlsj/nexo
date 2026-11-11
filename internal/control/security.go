package control

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/abcdlsj/nexo/pkg/config"
)

// IsPrivateHost reports whether a control address is safe for plaintext HTTP.
// Tailnet addresses live in the CGNAT range, so they count as private even
// though they are not RFC 1918.
func IsPrivateHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.Trim(host, "[]")
	if host == "" {
		return false
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".ts.net") || strings.HasSuffix(host, ".local") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Single-label names resolve inside a container network or VPN.
		return !strings.Contains(host, ".")
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// Tailscale/CGNAT 100.64.0.0/10.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return true
	}
	return false
}

// listenerTLS builds the control listener TLS config, or nil for plaintext.
func listenerTLS(cfg config.ControlTLSConfig) (*tls.Config, error) {
	certFile := strings.TrimSpace(cfg.CertFile)
	keyFile := strings.TrimSpace(cfg.KeyFile)
	clientCA := strings.TrimSpace(cfg.ClientCAFile)

	if certFile == "" && keyFile == "" && clientCA == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("control_plane.tls requires both cert_file and key_file")
	}

	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load control plane certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
	if clientCA != "" {
		pool, err := loadCertPool(clientCA)
		if err != nil {
			return nil, err
		}
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsConfig, nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("CA file %s contains no PEM certificate", path)
	}
	return pool, nil
}

// validateListen refuses combinations that would expose a plaintext management
// API to a routable address, or run it with an unprotected credential file.
func validateListen(listen string, tlsConfig *tls.Config, auth config.ControlAuthConfig) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("control_plane.listen %q: %w", listen, err)
	}
	if IsPrivateHost(host) {
		return nil
	}

	if tlsConfig == nil {
		return fmt.Errorf("control_plane.listen %q is public; configure control_plane.tls or bind a tailnet/VPN address", listen)
	}
	tokenFile := strings.TrimSpace(auth.TokenFile)
	if tokenFile == "" {
		return fmt.Errorf("control_plane.listen %q is public; control_plane.auth.token_file is required", listen)
	}
	if err := requirePrivateFile(tokenFile); err != nil {
		return err
	}
	if writeToken := strings.TrimSpace(auth.WriteTokenFile); writeToken != "" {
		if err := requirePrivateFile(writeToken); err != nil {
			return err
		}
	}
	return nil
}

func requirePrivateFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("control token file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("control token file %s must be mode 0600", path)
	}
	return nil
}

// parsePeerURL validates the peer address and enforces the tailnet-first rule:
// plaintext HTTP is only accepted for private addresses or an explicit opt-in.
func parsePeerURL(peer config.ControlPeerConfig) (*url.URL, error) {
	raw := strings.TrimSpace(peer.URL)
	u, err := url.Parse(raw)
	if err != nil {
		return nil, &APIError{Code: "invalid_peer_url", Message: "peer url is not valid"}
	}
	if u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return nil, &APIError{Code: "invalid_peer_url", Message: "peer url must be http(s) without credentials"}
	}
	if u.Scheme == "http" && !IsPrivateHost(u.Hostname()) && !peer.AllowInsecureHTTP {
		return nil, &APIError{
			Code:    "insecure_peer_url",
			Message: "plaintext HTTP to a public address is refused; use the tailnet address, https, or set allow_insecure_http explicitly",
		}
	}
	return u, nil
}

// peerHTTPClient builds a per-peer client. Each peer gets its own transport so
// one slow peer cannot exhaust another's connections.
func peerHTTPClient(peer config.ControlPeerConfig, timeout time.Duration) (*http.Client, error) {
	u, err := parsePeerURL(peer)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConnsPerHost:   2,
	}

	if u.Scheme == "https" {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if peer.ServerName != "" {
			tlsConfig.ServerName = peer.ServerName
		} else if net.ParseIP(u.Hostname()) != nil {
			tlsConfig.ServerName = u.Hostname()
		}
		if peer.InsecureSkipVerify {
			tlsConfig.InsecureSkipVerify = true
		}
		if peer.CAFile != "" {
			pool, err := loadCertPool(peer.CAFile)
			if err != nil {
				return nil, err
			}
			tlsConfig.RootCAs = pool
		}
		if peer.ClientCertFile != "" || peer.ClientKeyFile != "" {
			if peer.ClientCertFile == "" || peer.ClientKeyFile == "" {
				return nil, &APIError{Code: "invalid_peer_tls", Message: "client_cert_file and client_key_file must be set together"}
			}
			certificate, err := tls.LoadX509KeyPair(peer.ClientCertFile, peer.ClientKeyFile)
			if err != nil {
				return nil, &APIError{Code: "invalid_peer_tls", Message: "load client certificate: " + err.Error()}
			}
			tlsConfig.Certificates = []tls.Certificate{certificate}
		}
		transport.TLSClientConfig = tlsConfig
	}

	return &http.Client{Transport: transport, Timeout: timeout}, nil
}
