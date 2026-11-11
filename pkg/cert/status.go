package cert

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Info is the read-only certificate state for one served domain. It is safe to
// expose through the Web UI and the node control API: it never carries key
// material or ACME account data.
type Info struct {
	Domain         string
	Issuer         string
	NotAfter       time.Time
	DaysLeft       int
	Status         string // valid | expiring | error
	UsesWildcard   bool   // whether a wildcard certificate is reused
	WildcardDomain string // the wildcard pattern that supplied the certificate
}

// Inspect reports certificate state for every served domain. Domains without a
// certificate yield Status "error" and a zero NotAfter, which callers translate
// into a missing state.
func Inspect(certDir string, domains, wildcards []string) []Info {
	if certDir == "" {
		return nil
	}

	seen := make(map[string]bool, len(domains)+len(wildcards))
	out := make([]Info, 0, len(domains)+len(wildcards))

	add := func(domain string) {
		domain = strings.TrimSpace(domain)
		if domain == "" || seen[domain] {
			return
		}
		seen[domain] = true
		out = append(out, inspectDomain(certDir, domain, wildcards))
	}
	for _, domain := range domains {
		add(domain)
	}
	for _, wildcard := range wildcards {
		add(wildcard)
	}
	return out
}

func inspectDomain(certDir, domain string, wildcards []string) Info {
	if strings.HasPrefix(domain, "*.") {
		base := strings.TrimPrefix(domain, "*.")
		return readInfo(domain, filepath.Join(certDir, base+".crt"), filepath.Join(certDir, base+".key"))
	}

	certFile := filepath.Join(certDir, domain+".crt")
	keyFile := filepath.Join(certDir, domain+".key")
	if _, err := os.Stat(certFile); err == nil {
		return readInfo(domain, certFile, keyFile)
	}

	if wildcard, ok := wildcardFor(domain, wildcards); ok {
		base := strings.TrimPrefix(wildcard, "*.")
		certFile = filepath.Join(certDir, base+".crt")
		keyFile = filepath.Join(certDir, base+".key")
		if _, err := os.Stat(certFile); err == nil {
			info := readInfo(domain, certFile, keyFile)
			info.UsesWildcard = true
			info.WildcardDomain = wildcard
			return info
		}
	}

	return Info{Domain: domain, Status: "error"}
}

// wildcardFor mirrors config.Config.GetWildcardDomain without importing the
// config package (which would create an import cycle through proxy).
func wildcardFor(domain string, wildcards []string) (string, bool) {
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	candidate := "*." + parts[1]
	for _, wildcard := range wildcards {
		if wildcard == candidate {
			return wildcard, true
		}
	}
	return "", false
}

func readInfo(domain, certFile, keyFile string) Info {
	info := Info{Domain: domain, Status: "error"}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return info
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return info
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return info
	}

	info.Issuer = parsed.Issuer.CommonName
	info.NotAfter = parsed.NotAfter
	info.DaysLeft = int(time.Until(parsed.NotAfter).Hours() / 24)
	switch {
	case info.DaysLeft < 0:
		info.Status = "error"
	case info.DaysLeft < 30:
		info.Status = "expiring"
	default:
		info.Status = "valid"
	}

	if _, err := os.Stat(keyFile); err != nil {
		info.Status = "error"
	}
	return info
}
