package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type CertManager struct {
	client       *lego.Client
	account      *Account
	certificates map[string]*tls.Certificate
	challenges   map[string]string
	mu           sync.RWMutex
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

func NewCertManager() *CertManager {
	// Create account private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	account := &Account{
		Email: "admin@example.com", // TODO: Make configurable
		key:   privateKey,
	}

	config := lego.NewConfig(account)
	config.Certificate.KeyType = certcrypto.RSA2048
	config.CADirURL = lego.LEDirectoryProduction // or lego.LEDirectoryStaging for testing

	client, err := lego.NewClient(config)
	if err != nil {
		panic(err)
	}

	// Register account
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		panic(err)
	}
	account.Registration = reg

	// Add HTTP-01 challenge solver
	err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80"))
	if err != nil {
		panic(err)
	}

	return &CertManager{
		client:       client,
		account:      account,
		certificates: make(map[string]*tls.Certificate),
		challenges:   make(map[string]string),
	}
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

	// Save certificate
	tlsCert, err := tls.X509KeyPair(certificates.Certificate, certificates.PrivateKey)
	if err != nil {
		return err
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
