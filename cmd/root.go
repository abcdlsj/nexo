package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use:   "nexo",
		Short: "A simple HTTPS reverse proxy tool",
		Long: `Nexo is a simple HTTPS reverse proxy tool with automatic certificate management.
It supports wildcard certificates and configuration through YAML files.`,
	}
)

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is /etc/nexo/config.yaml)")
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// Default config locations
		viper.AddConfigPath("/etc/nexo")
		viper.AddConfigPath("$HOME/.nexo")
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName("config")
	}

	// Set default values
	viper.SetDefault("email", "admin@example.com")
	viper.SetDefault("cloudflare.api_token", "")
	viper.SetDefault("proxies", map[string]interface{}{})

	viper.AutomaticEnv()

	// Determine the config directory before reading the config
	configDir := "/etc/nexo"
	if os.Getuid() != 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting home directory: %v\n", err)
			os.Exit(1)
		}
		configDir = filepath.Join(home, ".nexo")
	}

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, create it with default values
			if err := os.MkdirAll(configDir, 0755); err != nil {
				fmt.Fprintf(os.Stderr, "Error creating config directory: %v\n", err)
				os.Exit(1)
			}

			configFile := filepath.Join(configDir, "config.yaml")
			viper.SetConfigFile(configFile)

			// Set base directory and cert directory in viper config
			viper.Set("base_dir", configDir)
			viper.Set("cert_dir", filepath.Join(configDir, "certs"))

			if err := viper.SafeWriteConfig(); err != nil {
				fmt.Fprintf(os.Stderr, "Error creating config file: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Created default config file at: %s\n", configFile)
		} else {
			fmt.Fprintf(os.Stderr, "Error reading config file: %v\n", err)
			os.Exit(1)
		}
	}

	// Ensure base_dir and cert_dir are set even when reading existing config
	if viper.GetString("base_dir") == "" {
		viper.Set("base_dir", configDir)
		viper.Set("cert_dir", filepath.Join(configDir, "certs"))
		// Save the updated config
		if err := SaveConfig(); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config with base directory: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Using config file: %s\n", viper.ConfigFileUsed())
	fmt.Printf("Base directory: %s\n", viper.GetString("base_dir"))

	// Validate required configuration
	if viper.GetString("cloudflare.api_token") == "" {
		fmt.Fprintf(os.Stderr, "Error: Cloudflare API token not configured. Please set it in the config file.\n")
		os.Exit(1)
	}
}

// SaveConfig saves the current configuration to file
func SaveConfig() error {
	return viper.WriteConfig()
}
