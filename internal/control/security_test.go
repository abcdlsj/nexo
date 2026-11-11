package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abcdlsj/nexo/pkg/config"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nexo test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca testCA) issue(t *testing.T, commonName string, isClient bool, dns []string, ips []net.IP) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if isClient {
		usage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usage,
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func writeFile(t *testing.T, dir, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPrivateHostDetection(t *testing.T) {
	private := []string{"127.0.0.1", "::1", "10.1.2.3", "192.168.1.9", "172.16.5.4", "100.64.0.1", "100.100.100.100", "fd7a:115c:a1e0::1", "localhost", "node.tail1234.ts.net", "nexo"}
	public := []string{"8.8.8.8", "203.0.113.9", "2001:4860:4860::8888", "example.com", ""}
	for _, host := range private {
		if !IsPrivateHost(host) {
			t.Errorf("expected private: %q", host)
		}
	}
	for _, host := range public {
		if IsPrivateHost(host) {
			t.Errorf("expected public: %q", host)
		}
	}
}

func TestPublicListenRequiresTLSAndToken(t *testing.T) {
	dir := t.TempDir()
	cfg := baseConfig()
	cfg.BaseDir = dir
	cfg.ControlPlane.Listen = "0.0.0.0:9090"

	if _, err := New(Options{Config: func() *config.Config { return cfg }, NodeID: "n", Listen: cfg.ControlPlane.Listen, BaseDir: dir}); err == nil {
		t.Fatal("plaintext public listener must be refused")
	}

	ca := newTestCA(t)
	certPEM, keyPEM := ca.issue(t, "control.example.com", false, []string{"control.example.com"}, nil)
	cfg.ControlPlane.TLS = config.ControlTLSConfig{
		CertFile: writeFile(t, dir, "server.crt", certPEM, 0600),
		KeyFile:  writeFile(t, dir, "server.key", keyPEM, 0600),
	}
	cfg.ControlPlane.Auth = config.ControlAuthConfig{}
	if _, err := New(Options{Config: func() *config.Config { return cfg }, NodeID: "n", Listen: cfg.ControlPlane.Listen, BaseDir: dir}); err == nil {
		t.Fatal("public listener without a token must be refused")
	}

	token := writeFile(t, dir, "token", []byte("token\n"), 0644)
	cfg.ControlPlane.Auth = config.ControlAuthConfig{TokenFile: token}
	if _, err := New(Options{Config: func() *config.Config { return cfg }, NodeID: "n", Listen: cfg.ControlPlane.Listen, BaseDir: dir}); err == nil {
		t.Fatal("world-readable token file must be refused")
	}
}

func TestPeerURLRequiresPrivateOrTLS(t *testing.T) {
	if _, err := parsePeerURL(config.ControlPeerConfig{URL: "http://203.0.113.10:9090"}); err == nil {
		t.Fatal("plaintext public peer must be refused")
	}
	if _, err := parsePeerURL(config.ControlPeerConfig{URL: "http://203.0.113.10:9090", AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("explicit opt-in rejected: %v", err)
	}
	if _, err := parsePeerURL(config.ControlPeerConfig{URL: "http://100.100.1.2:9090"}); err != nil {
		t.Fatalf("tailnet peer rejected: %v", err)
	}
	if _, err := parsePeerURL(config.ControlPeerConfig{URL: "https://nexo.example.com"}); err != nil {
		t.Fatalf("https peer rejected: %v", err)
	}
}

func TestControlListenerMutualTLS(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	serverCert, serverKey := ca.issue(t, "127.0.0.1", false, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	clientCert, clientKey := ca.issue(t, "peer", true, nil, nil)
	caFile := writeFile(t, dir, "ca.crt", ca.pem, 0600)

	store := &testStore{cfg: baseConfig()}
	cfg := store.get()
	cfg.BaseDir = dir
	cfg.CertDir = filepath.Join(dir, "certs")
	cfg.ControlPlane.Listen = "127.0.0.1:0"
	cfg.ControlPlane.Node.ID = "node-a"
	cfg.ControlPlane.Node.Name = "Node A"
	cfg.ControlPlane.Auth.TokenFile = writeFile(t, dir, "read.token", []byte("read-token\n"), 0600)
	cfg.ControlPlane.Auth.WriteTokenFile = writeFile(t, dir, "write.token", []byte("write-token\n"), 0600)
	cfg.ControlPlane.TLS = config.ControlTLSConfig{
		CertFile:     writeFile(t, dir, "server.crt", serverCert, 0600),
		KeyFile:      writeFile(t, dir, "server.key", serverKey, 0600),
		ClientCAFile: caFile,
	}

	ctl, err := New(Options{
		Config:    store.get,
		NodeID:    cfg.ControlPlane.Node.ID,
		NodeName:  cfg.ControlPlane.Node.Name,
		StartedAt: time.Now().Add(-time.Minute),
		Listen:    cfg.ControlPlane.Listen,
		BaseDir:   dir,
		Mutate:    store.mutate,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ctl.Start(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for ctl.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if ctl.Addr() == "" {
		t.Fatal("control listener did not start")
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.pem)
	clientPair, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}

	withCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientPair},
		ServerName:   "127.0.0.1",
	}}}
	req, _ := http.NewRequest(http.MethodGet, "https://"+ctl.Addr()+"/control/v1/node", nil)
	req.Header.Set("Authorization", "Bearer read-token")
	resp, err := withCert.Do(req)
	if err != nil {
		t.Fatalf("mTLS request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mTLS status: %d", resp.StatusCode)
	}

	withoutCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    caPool,
		ServerName: "127.0.0.1",
	}}}
	req, _ = http.NewRequest(http.MethodGet, "https://"+ctl.Addr()+"/control/v1/node", nil)
	req.Header.Set("Authorization", "Bearer read-token")
	if resp, err := withoutCert.Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("request without a client certificate was accepted")
	}
}

func TestFederationOverTLS(t *testing.T) {
	store := &testStore{cfg: baseConfig()}
	ctl, handler := newTestServer(t, store)
	peer := httptest.NewTLSServer(handler)
	defer peer.Close()

	dir := t.TempDir()
	caFile := writeFile(t, dir, "peer-ca.pem",
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peer.Certificate().Raw}), 0600)

	fed := NewFederation(func() *Snapshot { return ctl.Snapshot(0) }, func() config.CoordinatorConfig {
		return config.CoordinatorConfig{Enabled: true, Peers: []config.ControlPeerConfig{{
			ID:        "node-a",
			URL:       peer.URL,
			TokenFile: writeToken(t, dir, "read-token"),
			CAFile:    caFile,
		}}}
	}, ctl.NodeID())

	fed.poll(context.Background(), fed.cfg())
	if state := fedSnapshotState(fed, ctl); state != StateFresh {
		t.Fatalf("expected fresh over TLS, got %s", state)
	}
}

func TestFederationRejectsPublicPlaintextPeer(t *testing.T) {
	store := &testStore{cfg: baseConfig()}
	ctl, _ := newTestServer(t, store)

	fed := NewFederation(func() *Snapshot { return ctl.Snapshot(0) }, func() config.CoordinatorConfig {
		return config.CoordinatorConfig{Enabled: true, Peers: []config.ControlPeerConfig{{
			ID:        "node-a",
			URL:       "http://203.0.113.10:9090",
			TokenFile: writeToken(t, t.TempDir(), "read-token"),
		}}}
	}, ctl.NodeID())

	fed.poll(context.Background(), fed.cfg())
	if state := fedSnapshotState(fed, ctl); state != StateMisconfigured {
		t.Fatalf("expected misconfigured, got %s", state)
	}
}

// Ensure the snapshot envelope decodes from a TLS peer without surprises.
func TestSnapshotJSONRoundTrip(t *testing.T) {
	store := &testStore{cfg: baseConfig()}
	ctl, _ := newTestServer(t, store)
	body, err := json.Marshal(Envelope{APIVersion: APIVersion, Kind: "Snapshot", Data: ctl.Snapshot(0)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"api_version":"`+APIVersion+`"`) {
		t.Fatalf("unexpected envelope: %s", body)
	}
	var decoded Envelope
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
}
