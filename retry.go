package main

import (
	"net/url"
	"strings"
	"time"

	"github.com/charmbracelet/log"
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
				log.Info("Retrying certificate acquisition", "domain", domain)
				if err := s.certManager.ObtainCert(domain); err != nil {
					log.Error("Retry failed", "domain", domain, "err", err)
					s.addFailedCert(domain, err)
				} else {
					log.Info("Successfully obtained certificate", "domain", domain)
					s.failedCertsMu.Lock()
					delete(s.failedCerts, domain)
					s.failedCertsMu.Unlock()

					if strings.HasPrefix(domain, "*.") {
						log.Info("Successfully obtained wildcard certificate, reloading all proxy configurations", "domain", domain)
						if err := s.reloadConfig(); err != nil {
							log.Error("Error reloading config after successful wildcard cert retry", "err", err)
						}
					} else {
						var proxyConfig ProxyConfig
						if err := gViper.UnmarshalKey("proxies:"+domain, &proxyConfig); err != nil {
							log.Error("Error loading proxy config after cert retry", "domain", domain, "err", err)
							continue
						}

						targetURL, err := url.Parse(proxyConfig.Target)
						if err != nil {
							log.Error("Error parsing target URL after cert retry", "domain", domain, "err", err)
							continue
						}

						s.mu.Lock()
						s.proxies[domain] = s.createReverseProxy(targetURL, domain)
						s.mu.Unlock()
						log.Info("Successfully reconfigured proxy", "domain", domain)
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
	log.Info("Added domain to retry queue",
		"domain", domain,
		"retry_time", retryTime.Format("2006-01-02 15:04:05 UTC"))
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
			log.Error("Error parsing proxy config", "domain", domain, "err", err)
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
					log.Info("Removed failed cert record as it now uses wildcard cert",
						"domain", domain,
						"wildcard_domain", wildcardDomain)
					continue
				}
			}
			delete(s.failedCerts, domain)
			log.Info("Removed failed cert record as it is no longer in configuration", "domain", domain)
		}
	}
}
