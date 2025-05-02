package cert

import (
	"crypto"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

// Config holds the configuration for certificate management
type Config struct {
	CertDir    string
	Email      string
	CFAPIToken string
}

// Manager handles certificate operations
type Manager struct {
	config Config
	mu     sync.RWMutex
	certs  map[string]*tls.Certificate
}

// New creates a new certificate manager
func New(cfg Config) *Manager {
	return &Manager{
		config: cfg,
		certs:  make(map[string]*tls.Certificate),
	}
}

// GetCertificate implements the tls.Config.GetCertificate function
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	cert, ok := m.certs[hello.ServerName]
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no certificate for domain: %s", hello.ServerName)
	}
	return cert, nil
}

// ObtainCert obtains a new certificate for the given domain
func (m *Manager) ObtainCert(domain string) error {
	// Create certificate directory if not exists
	if err := os.MkdirAll(m.config.CertDir, 0755); err != nil {
		return fmt.Errorf("failed to create cert directory: %v", err)
	}

	// Initialize ACME client
	client, err := m.createClient()
	if err != nil {
		return fmt.Errorf("failed to create ACME client: %v", err)
	}

	// Request certificate
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("failed to obtain certificate: %v", err)
	}

	// Save certificate
	return m.saveCertificate(domain, certificates)
}

func (m *Manager) createClient() (*lego.Client, error) {
	user := &User{
		Email: m.config.Email,
		key:   certcrypto.RSA2048,
	}

	config := lego.NewConfig(user)
	config.CADirURL = lego.LEDirectoryProduction
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	cfProvider, err := cloudflare.NewDNSProviderConfig(&cloudflare.Config{
		AuthToken:          m.config.CFAPIToken,
		TTL:                120,
		PropagationTimeout: 180 * time.Second,
		PollingInterval:    2 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create cloudflare provider: %v", err)
	}

	if err := client.Challenge.SetDNS01Provider(cfProvider,
		dns01.AddRecursiveNameservers([]string{"1.1.1.1:53", "8.8.8.8:53"}),
		dns01.DisableCompletePropagationRequirement()); err != nil {
		return nil, err
	}

	return client, nil
}

func (m *Manager) saveCertificate(domain string, cert *certificate.Resource) error {
	certPath := filepath.Join(m.config.CertDir, domain+".crt")
	keyPath := filepath.Join(m.config.CertDir, domain+".key")

	if err := os.WriteFile(certPath, cert.Certificate, 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}

	if err := os.WriteFile(keyPath, cert.PrivateKey, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %v", err)
	}

	tlsCert, err := tls.X509KeyPair(cert.Certificate, cert.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	m.mu.Lock()
	m.certs[domain] = &tlsCert
	m.mu.Unlock()

	return nil
}

// LoadCertificate loads an existing certificate from disk
func (m *Manager) LoadCertificate(domain string) error {
	certPath := filepath.Join(m.config.CertDir, domain+".crt")
	keyPath := filepath.Join(m.config.CertDir, domain+".key")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.certs[domain] = &cert
	m.mu.Unlock()

	return nil
}

// User implements acme.User
type User struct {
	Email        string
	Registration *registration.Resource
	key          certcrypto.KeyType
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}
