package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	domain string
	target string
)

type ProxyConfig struct {
	Target string `json:"target" yaml:"target"`
}

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Manage proxy configurations",
	Long:  `Add, remove, or list proxy configurations.`,
}

var proxyAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new proxy configuration",
	Long:  `Add a new proxy configuration mapping a domain to a target.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if domain == "" || target == "" {
			return fmt.Errorf("domain and target are required")
		}

		// Validate target URL
		targetURL, err := url.Parse(target)
		if err != nil {
			return fmt.Errorf("invalid target URL: %v", err)
		}
		if targetURL.Scheme == "" {
			targetURL.Scheme = "http"
		}

		// Get existing proxies
		proxies := viper.GetStringMap("proxies")
		if proxies == nil {
			proxies = make(map[string]interface{})
		}

		// Add new proxy
		proxies[domain] = ProxyConfig{
			Target: targetURL.String(),
		}

		// Save to config
		viper.Set("proxies", proxies)
		if err := SaveConfig(); err != nil {
			return fmt.Errorf("failed to save config: %v", err)
		}

		fmt.Printf("Added proxy: %s -> %s\n", domain, targetURL.String())
		return nil
	},
}

var proxyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all proxy configurations",
	Long:  `List all configured domain to target mappings.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		proxies := viper.GetStringMap("proxies")
		if len(proxies) == 0 {
			fmt.Println("No proxy configurations found")
			return nil
		}

		fmt.Println("Domain -> Target")
		fmt.Println("----------------")
		for domain, proxy := range proxies {
			if p, ok := proxy.(map[string]interface{}); ok {
				fmt.Printf("%s -> %s\n", domain, p["target"])
			}
		}
		return nil
	},
}

var proxyRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove a proxy configuration",
	Long:  `Remove a proxy configuration for a specific domain.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if domain == "" {
			return fmt.Errorf("domain is required")
		}

		proxies := viper.GetStringMap("proxies")
		if proxies == nil || proxies[domain] == nil {
			return fmt.Errorf("domain %s not found", domain)
		}

		delete(proxies, domain)
		viper.Set("proxies", proxies)
		if err := SaveConfig(); err != nil {
			return fmt.Errorf("failed to save config: %v", err)
		}

		fmt.Printf("Removed proxy for domain: %s\n", domain)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(proxyCmd)
	proxyCmd.AddCommand(proxyAddCmd)
	proxyCmd.AddCommand(proxyListCmd)
	proxyCmd.AddCommand(proxyRemoveCmd)

	proxyAddCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain to proxy (e.g., example.com or *.example.com)")
	proxyAddCmd.Flags().StringVarP(&target, "target", "t", "", "Target to proxy to (e.g., localhost:8080)")
	proxyRemoveCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain to remove")
}
