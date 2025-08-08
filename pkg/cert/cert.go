package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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
	user   *User
}

// New creates a new certificate manager
func New(cfg Config) (*Manager, error) {
	// Create certificate directory if not exists
	if err := os.MkdirAll(cfg.CertDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cert directory: %v", err)
	}

	// Create ACME client first (load or create account)
	c, u, err := createClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME client: %v", err)
	}

	m := &Manager{
		config: cfg,
		certs:  make(map[string]*tls.Certificate),
		client: c,
		user:   u,
	}

	// Load existing certificates from disk
	if err := m.loadCerts(); err != nil {
		log.Warn("Failed to load certificates from disk", "err", err)
	}

	return m, nil
}

// createClient creates a new ACME client with the given configuration
func createClient(cfg Config) (*lego.Client, *User, error) {
	// Try to load existing account key
	accountKeyPath := filepath.Join(cfg.CertDir, "account.key")
	var key crypto.PrivateKey
	if data, err := os.ReadFile(accountKeyPath); err == nil {
		if k, err := parseECDSAPrivateKeyFromPEM(data); err == nil {
			key = k
		}
	}
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
		}
		if err := saveECDSAPrivateKeyToPEM(accountKeyPath, key.(*ecdsa.PrivateKey)); err != nil {
			log.Warn("failed to persist account key", "err", err)
		}
	}

	u := &User{Email: cfg.Email, key: key}
	c := lego.NewConfig(u)
	c.CADirURL = lego.LEDirectoryProduction
	c.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(c)
	if err != nil {
		return nil, nil, err
	}

	p, err := cloudflare.NewDNSProviderConfig(&cloudflare.Config{
		AuthToken:          cfg.CFAPIToken,
		TTL:                120,
		PropagationTimeout: 180 * time.Second,
		PollingInterval:    2 * time.Second,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cloudflare provider: %v", err)
	}

	if err := client.Challenge.SetDNS01Provider(p,
		dns01.AddRecursiveNameservers([]string{"1.1.1.1:53", "8.8.8.8:53"})); err != nil {
		return nil, nil, err
	}

	// Try to load existing registration marker or register
	accountRegPath := filepath.Join(cfg.CertDir, "account.reg")
	if _, err := os.Stat(accountRegPath); err == nil {
		reg, err := client.Registration.QueryRegistration()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to query registration: %v", err)
		}
		u.Registration = reg
	} else {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			// fallback to query if already registered remotely
			reg, qerr := client.Registration.QueryRegistration()
			if qerr != nil {
				return nil, nil, fmt.Errorf("failed to register user: %v", err)
			}
			u.Registration = reg
		} else {
			u.Registration = reg
			_ = os.WriteFile(accountRegPath, []byte("registered"), 0600)
		}
	}

	return client, u, nil
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

		name := strings.TrimSuffix(f.Name(), ".crt")
		crtPath := filepath.Join(m.config.CertDir, f.Name())
		keyPath := filepath.Join(m.config.CertDir, name+".key")

		crt, err := os.ReadFile(crtPath)
		if err != nil {
			log.Error("Failed to read certificate file", "domain", name, "err", err)
			continue
		}

		key, err := os.ReadFile(keyPath)
		if err != nil {
			log.Error("Failed to read key file", "domain", name, "err", err)
			continue
		}

		cert, err := tls.X509KeyPair(crt, key)
		if err != nil {
			log.Error("Failed to parse certificate", "domain", name, "err", err)
			continue
		}

		// Parse the certificate to get the expiry date
		if len(cert.Certificate) > 0 {
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				log.Error("Failed to parse X509 certificate", "domain", name, "err", err)
				continue
			}
			cert.Leaf = x509Cert

			// Skip expired certificates
			if time.Now().After(x509Cert.NotAfter) {
				log.Info("Skipping expired certificate", "domain", name, "expiry", x509Cert.NotAfter)
				continue
			}
		}

		m.mu.Lock()
		m.certs[name] = &cert
		m.mu.Unlock()
		log.Info("Loaded certificate", "domain", name)
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
	req := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certs, err := m.client.Certificate.Obtain(req)
	if err != nil {
		return fmt.Errorf("failed to obtain certificate: %v", err)
	}

	return m.saveCertificate(domain, certs)
}

func (m *Manager) saveCertificate(domain string, cert *certificate.Resource) error {
	crtPath := filepath.Join(m.config.CertDir, domain+".crt")
	keyPath := filepath.Join(m.config.CertDir, domain+".key")

	if err := os.WriteFile(crtPath, cert.Certificate, 0600); err != nil {
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

// Helpers for PEM ECDSA key
func saveECDSAPrivateKeyToPEM(path string, key *ecdsa.PrivateKey) error {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	pemBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	return os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0600)
}

func parseECDSAPrivateKeyFromPEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("invalid ECDSA private key PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}
