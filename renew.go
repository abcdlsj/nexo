package main

import (
	"strings"
	"time"

	"github.com/charmbracelet/log"
)

// getWildcardDomain returns the wildcard domain for a given domain
// e.g., "api.example.com" -> "*.example.com"
func getWildcardDomain(domain string) string {
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) != 2 {
		return ""
	}
	return "*." + parts[1]
}

func (s *Server) autoRenewCertificates() {
	ticker := time.NewTicker(24 * time.Hour) // Check daily
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.mu.RLock()
			// 收集所有需要的证书域名
			certDomains := make(map[string]bool)
			for domain := range s.proxies {
				// 获取域名的配置
				var proxyConfig ProxyConfig
				if err := gViper.UnmarshalKey("proxies:"+domain, &proxyConfig); err != nil {
					log.Error("Error getting config", "domain", domain, "err", err)
					continue
				}

				if proxyConfig.UseWildcardCert {
					if wildcardDomain := getWildcardDomain(domain); wildcardDomain != "" {
						certDomains[wildcardDomain] = true
					}
				} else {
					certDomains[domain] = true
				}
			}
			s.mu.RUnlock()

			// 更新所有需要的证书
			for domain := range certDomains {
				if err := s.certManager.ObtainCert(domain); err != nil {
					log.Error("Error renewing certificate", "domain", domain, "err", err)
				} else {
					log.Info("Successfully renewed certificate", "domain", domain)
				}
			}
		}
	}
}
