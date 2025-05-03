package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
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
	client *lego.Client
}

// New creates a new certificate manager
func New(cfg Config) (*Manager, error) {
	// Create certificate directory if not exists
	if err := os.MkdirAll(cfg.CertDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cert directory: %v", err)
	}

	// Create ACME client first
	client, err := createClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME client: %v", err)
	}

	m := &Manager{
		config: cfg,
		certs:  make(map[string]*tls.Certificate),
		client: client,
	}

	// Load existing certificates from disk
	if err := m.loadCerts(); err != nil {
		log.Warn("Failed to load certificates from disk", "err", err)
	}

	return m, nil
}

// createClient creates a new ACME client with the given configuration
func createClient(cfg Config) (*lego.Client, error) {
	// Generate private key for user
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	user := &User{
		Email: cfg.Email,
		key:   privateKey,
	}

	config := lego.NewConfig(user)
	config.CADirURL = lego.LEDirectoryProduction
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	cfProvider, err := cloudflare.NewDNSProviderConfig(&cloudflare.Config{
		AuthToken:          cfg.CFAPIToken,
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

	// Register user if necessary
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("failed to register user: %v", err)
	}
	user.Registration = reg

	return client, nil
}

// loadCerts loads all existing certificates from the certificate directory
func (m *Manager) loadCerts() error {
	files, err := os.ReadDir(m.config.CertDir)
	if err != nil {
		return fmt.Errorf("failed to read certificate directory: %v", err)
	}

	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".crt") {
			continue
		}

		domain := strings.TrimSuffix(f.Name(), ".crt")
		certPath := filepath.Join(m.config.CertDir, f.Name())
		keyPath := filepath.Join(m.config.CertDir, domain+".key")

		certPEMBlock, err := os.ReadFile(certPath)
		if err != nil {
			log.Error("Failed to read certificate file", "domain", domain, "err", err)
			continue
		}

		keyPEMBlock, err := os.ReadFile(keyPath)
		if err != nil {
			log.Error("Failed to read key file", "domain", domain, "err", err)
			continue
		}

		cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
		if err != nil {
			log.Error("Failed to parse certificate", "domain", domain, "err", err)
			continue
		}

		// Parse the certificate to get the expiry date
		if len(cert.Certificate) > 0 {
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				log.Error("Failed to parse X509 certificate", "domain", domain, "err", err)
				continue
			}
			cert.Leaf = x509Cert

			// Skip expired certificates
			if time.Now().After(x509Cert.NotAfter) {
				log.Info("Skipping expired certificate", "domain", domain, "expiry", x509Cert.NotAfter)
				continue
			}
		}

		m.mu.Lock()
		m.certs[domain] = &cert
		m.mu.Unlock()
		log.Info("Loaded certificate", "domain", domain)
	}

	return nil
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
	// Request certificate
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := m.client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("failed to obtain certificate: %v", err)
	}

	// Save certificate
	return m.saveCertificate(domain, certificates)
}

func (m *Manager) saveCertificate(domain string, cert *certificate.Resource) error {
	certPath := filepath.Join(m.config.CertDir, domain+".crt")
	keyPath := filepath.Join(m.config.CertDir, domain+".key")

	if err := os.WriteFile(certPath, cert.Certificate, 0600); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}

	if err := os.WriteFile(keyPath, cert.PrivateKey, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %v", err)
	}

	tlsCert, err := tls.X509KeyPair(cert.Certificate, cert.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Parse the certificate to get the expiry date
	if len(tlsCert.Certificate) > 0 {
		x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %v", err)
		}
		tlsCert.Leaf = x509Cert
	}

	m.mu.Lock()
	m.certs[domain] = &tlsCert
	m.mu.Unlock()

	return nil
}

// User implements acme.User
type User struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
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
