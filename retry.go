package main

import (
	"net/url"
	"strings"
	"time"

	"github.com/charmbracelet/log"
)

func (s *Server) retryCerts() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			var domains []string

			s.failedmu.RLock()
			for domain, retryTime := range s.failed {
				if now.After(retryTime) {
					domains = append(domains, domain)
				}
			}
			s.failedmu.RUnlock()

			for _, domain := range domains {
				log.Info("Retrying certificate acquisition", "domain", domain)
				if err := s.certm.ObtainCert(domain); err != nil {
					log.Error("Retry failed", "domain", domain, "err", err)
					s.addFailedCert(domain, err)
				} else {
					log.Info("Successfully obtained certificate", "domain", domain)
					s.failedmu.Lock()
					delete(s.failed, domain)
					s.failedmu.Unlock()

					if strings.HasPrefix(domain, "*.") {
						log.Info("Successfully obtained wildcard certificate, reloading all proxy configurations", "domain", domain)
						if err := s.reload(); err != nil {
							log.Error("Error reloading config after successful wildcard cert retry", "err", err)
						}
					} else {
						var cfg ProxyConfig
						if err := gViper.UnmarshalKey("proxies:"+domain, &cfg); err != nil {
							log.Error("Error loading proxy config after cert retry", "domain", domain, "err", err)
							continue
						}

						target, err := url.Parse(cfg.Target)
						if err != nil {
							log.Error("Error parsing target URL after cert retry", "domain", domain, "err", err)
							continue
						}

						s.mu.Lock()
						s.proxies[domain] = s.createReverseProxy(target, domain)
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
	s.failedmu.Lock()
	s.failed[domain] = retryTime
	s.failedmu.Unlock()
	log.Info("Added domain to retry queue",
		"domain", domain,
		"retry_time", retryTime.Format("2006-01-02 15:04:05 UTC"))
}

func (s *Server) checkFailedCerts() {
	proxies := gViper.GetStringMap("proxies")
	if len(proxies) == 0 {
		return
	}

	s.failedmu.Lock()
	defer s.failedmu.Unlock()

	certs := make(map[string]bool)
	for domain := range proxies {
		var cfg ProxyConfig
		if err := gViper.UnmarshalKey("proxies:"+domain, &cfg); err != nil {
			log.Error("Error parsing proxy config", "domain", domain, "err", err)
			continue
		}

		if cfg.UseWildcardCert {
			if wildcardDomain := getWildcardDomain(domain); wildcardDomain != "" {
				certs[wildcardDomain] = true
			}
		} else {
			certs[domain] = true
		}
	}

	for domain := range s.failed {
		if !certs[domain] {
			parts := strings.SplitN(domain, ".", 2)
			if len(parts) == 2 {
				wildcardDomain := "*." + parts[1]
				if certs[wildcardDomain] {
					delete(s.failed, domain)
					log.Info("Removed failed cert record as it now uses wildcard cert",
						"domain", domain,
						"wildcard_domain", wildcardDomain)
					continue
				}
			}
			delete(s.failed, domain)
			log.Info("Removed failed cert record as it is no longer in configuration", "domain", domain)
		}
	}
}
