package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

// Config holds all the configuration needed for CertManager
type Config struct {
	CertDir    string
	Email      string
	CFAPIToken string
}

type CertManager struct {
	client       *lego.Client
	account      *Account
	certificates map[string]*tls.Certificate
	challenges   map[string]string
	mu           sync.RWMutex
	certDir      string
}

type Account struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (a *Account) GetEmail() string {
	return a.Email
}

func (a *Account) GetRegistration() *registration.Resource {
	return a.Registration
}

func (a *Account) GetPrivateKey() crypto.PrivateKey {
	return a.key
}

func NewCertManager(cfg Config) *CertManager {
	// Validate configuration
	if cfg.CertDir == "" {
		panic("cert_dir not provided in config")
	}

	if cfg.CFAPIToken == "" {
		fmt.Fprintf(os.Stderr, "Error: Cloudflare API token not found in config\n")
		os.Exit(1)
	}

	if cfg.Email == "" {
		fmt.Fprintf(os.Stderr, "Error: Email not found in config\n")
		os.Exit(1)
	}

	// Create certificates directory with all parent directories
	if err := os.MkdirAll(cfg.CertDir, 0700); err != nil {
		panic(fmt.Sprintf("Failed to create certificate directory: %v", err))
	}

	// Create account private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	account := &Account{
		Email: cfg.Email,
		key:   privateKey,
	}

	config := lego.NewConfig(account)
	config.Certificate.KeyType = certcrypto.RSA2048
	config.CADirURL = lego.LEDirectoryProduction // or lego.LEDirectoryStaging for testing

	client, err := lego.NewClient(config)
	if err != nil {
		panic(err)
	}

	// Configure Cloudflare DNS provider
	cfProvider, err := cloudflare.NewDNSProviderConfig(&cloudflare.Config{
		AuthToken:          cfg.CFAPIToken,
		TTL:                120,
		PropagationTimeout: 180 * time.Second,
		PollingInterval:    2 * time.Second,
	})
	if err != nil {
		panic(err)
	}

	// Set Cloudflare as DNS provider
	err = client.Challenge.SetDNS01Provider(cfProvider)
	if err != nil {
		panic(err)
	}

	// Register account
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		panic(err)
	}
	account.Registration = reg

	cm := &CertManager{
		client:       client,
		account:      account,
		certificates: make(map[string]*tls.Certificate),
		certDir:      cfg.CertDir,
	}

	// Load existing certificates from disk
	if err := cm.loadCertificatesFromDisk(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to load certificates from disk: %v\n", err)
	}

	return cm
}

func (cm *CertManager) loadCertificatesFromDisk() error {
	files, err := os.ReadDir(cm.certDir)
	if err != nil {
		return fmt.Errorf("failed to read certificate directory: %v", err)
	}

	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".crt") {
			continue
		}

		domain := strings.TrimSuffix(f.Name(), ".crt")
		certPath := filepath.Join(cm.certDir, f.Name())
		keyPath := filepath.Join(cm.certDir, domain+".key")

		certPEMBlock, err := os.ReadFile(certPath)
		if err != nil {
			continue
		}

		keyPEMBlock, err := os.ReadFile(keyPath)
		if err != nil {
			continue
		}

		cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
		if err != nil {
			continue
		}

		// Parse the certificate to get the expiry date
		if len(cert.Certificate) > 0 {
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				continue
			}
			cert.Leaf = x509Cert

			// Skip expired certificates
			if time.Now().After(x509Cert.NotAfter) {
				continue
			}
		}

		cm.mu.Lock()
		cm.certificates[domain] = &cert
		cm.mu.Unlock()
	}

	return nil
}

func (cm *CertManager) saveCertificateToDisk(domain string, certData *certificate.Resource) error {
	// Save certificate
	certPath := filepath.Join(cm.certDir, domain+".crt")
	if err := os.WriteFile(certPath, certData.Certificate, 0600); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}

	// Save private key
	keyPath := filepath.Join(cm.certDir, domain+".key")
	if err := os.WriteFile(keyPath, certData.PrivateKey, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %v", err)
	}

	return nil
}

func (cm *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := hello.ServerName

	cm.mu.RLock()
	cert, ok := cm.certificates[domain]
	cm.mu.RUnlock()

	if !ok {
		// Try wildcard certificate
		parts := strings.SplitN(domain, ".", 2)
		if len(parts) == 2 {
			wildcardDomain := "*." + parts[1]
			cm.mu.RLock()
			cert, ok = cm.certificates[wildcardDomain]
			cm.mu.RUnlock()
		}
	}

	if !ok {
		return nil, fmt.Errorf("no certificate found for domain: %s", domain)
	}

	return cert, nil
}

func (cm *CertManager) ObtainCert(domain string) error {
	// Check if we already have a valid certificate
	cm.mu.RLock()
	cert, ok := cm.certificates[domain]
	cm.mu.RUnlock()

	if ok && time.Now().Before(cert.Leaf.NotAfter.Add(-30*24*time.Hour)) {
		return nil
	}

	// Request certificate
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := cm.client.Certificate.Obtain(request)
	if err != nil {
		return err
	}

	// Save certificate to disk
	if err := cm.saveCertificateToDisk(domain, certificates); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}

	// Load into memory
	tlsCert, err := tls.X509KeyPair(certificates.Certificate, certificates.PrivateKey)
	if err != nil {
		return err
	}

	// Parse the certificate to get the expiry date
	if len(tlsCert.Certificate) > 0 {
		x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %v", err)
		}
		tlsCert.Leaf = x509Cert
	}

	cm.mu.Lock()
	cm.certificates[domain] = &tlsCert
	cm.mu.Unlock()

	return nil
}

func (cm *CertManager) HandleHTTPChallenge(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		return false
	}

	token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
	cm.mu.RLock()
	keyAuth, ok := cm.challenges[token]
	cm.mu.RUnlock()

	if !ok {
		http.NotFound(w, r)
		return true
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(keyAuth))
	return true
}
