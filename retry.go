package main

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

func (s *Server) retryFailedCertificates() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			var domainsToRetry []string

			s.failedCertsMu.RLock()
			for domain, retryTime := range s.failedCerts {
				if now.After(retryTime) {
					domainsToRetry = append(domainsToRetry, domain)
				}
			}
			s.failedCertsMu.RUnlock()

			for _, domain := range domainsToRetry {
				fmt.Printf("Retrying certificate acquisition for %s\n", domain)
				if err := s.certManager.ObtainCert(domain); err != nil {
					fmt.Printf("Retry failed for %s: %v\n", domain, err)
					s.addFailedCert(domain, err)
				} else {
					fmt.Printf("Successfully obtained certificate for %s\n", domain)
					s.failedCertsMu.Lock()
					delete(s.failedCerts, domain)
					s.failedCertsMu.Unlock()

					if strings.HasPrefix(domain, "*.") {
						fmt.Printf("Successfully obtained wildcard certificate for %s, reloading all proxy configurations\n", domain)
						if err := s.reloadConfig(); err != nil {
							fmt.Printf("Error reloading config after successful wildcard cert retry: %v\n", err)
						}
					} else {
						var proxyConfig ProxyConfig
						if err := gViper.UnmarshalKey("proxies:"+domain, &proxyConfig); err != nil {
							fmt.Printf("Error loading proxy config for %s after cert retry: %v\n", domain, err)
							continue
						}

						targetURL, err := url.Parse(proxyConfig.Target)
						if err != nil {
							fmt.Printf("Error parsing target URL for %s after cert retry: %v\n", domain, err)
							continue
						}

						s.mu.Lock()
						s.proxies[domain] = s.createReverseProxy(targetURL, domain)
						s.mu.Unlock()
						fmt.Printf("Successfully reconfigured proxy for %s\n", domain)
					}
				}
			}
		}
	}
}

func parseRetryTime(err error) (time.Time, bool) {
	errStr := err.Error()
	if strings.Contains(errStr, "retry after") {
		parts := strings.Split(errStr, "retry after")
		if len(parts) > 1 {
			timeStr := strings.Split(parts[1], "UTC")[0]
			retryTime, err := time.Parse("2006-01-02 15:04:05", strings.TrimSpace(timeStr))
			if err == nil {
				return retryTime, true
			}
		}
	}
	return time.Now().Add(1 * time.Hour), false
}

func (s *Server) addFailedCert(domain string, err error) {
	retryTime, _ := parseRetryTime(err)
	s.failedCertsMu.Lock()
	s.failedCerts[domain] = retryTime
	s.failedCertsMu.Unlock()
	fmt.Printf("Added %s to retry queue, will retry after %v\n", domain, retryTime.Format("2006-01-02 15:04:05 UTC"))
}

func (s *Server) reevaluateFailedCerts() {
	proxies := gViper.GetStringMap("proxies")
	if len(proxies) == 0 {
		return
	}

	s.failedCertsMu.Lock()
	defer s.failedCertsMu.Unlock()

	currentCerts := make(map[string]bool)
	for domain := range proxies {
		var proxyConfig ProxyConfig
		if err := gViper.UnmarshalKey("proxies:"+domain, &proxyConfig); err != nil {
			fmt.Printf("Error parsing proxy config for %s: %v\n", domain, err)
			continue
		}

		if proxyConfig.UseWildcardCert {
			if wildcardDomain := getWildcardDomain(domain); wildcardDomain != "" {
				currentCerts[wildcardDomain] = true
			}
		} else {
			currentCerts[domain] = true
		}
	}

	for domain := range s.failedCerts {
		if !currentCerts[domain] {
			parts := strings.SplitN(domain, ".", 2)
			if len(parts) == 2 {
				wildcardDomain := "*." + parts[1]
				if currentCerts[wildcardDomain] {
					delete(s.failedCerts, domain)
					fmt.Printf("Removed failed cert record for %s as it now uses wildcard cert %s\n", domain, wildcardDomain)
					continue
				}
			}
			delete(s.failedCerts, domain)
			fmt.Printf("Removed failed cert record for %s as it is no longer in configuration\n", domain)
		}
	}
}
