package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	gViper  *viper.Viper
	rootCmd = &cobra.Command{
		Use:   "nexo",
		Short: "A simple HTTPS reverse proxy tool",
		Long: `Nexo is a simple HTTPS reverse proxy tool with automatic certificate management.
It supports wildcard certificates and configuration through YAML files.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			server := New()
			return server.Start()
		},
	}
)

func Execute() error {
	return rootCmd.Execute()
}

func GetViper() *viper.Viper {
	return gViper
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is /etc/nexo/config.yaml)")
}

func initConfig() {
	// Create a new Viper instance with : as key delimiter
	gViper = viper.NewWithOptions(viper.KeyDelimiter(":"))

	if cfgFile != "" {
		gViper.SetConfigFile(cfgFile)
	} else {
		// Default config locations
		gViper.AddConfigPath("/etc/nexo")
		gViper.AddConfigPath("$HOME/.nexo")
		gViper.AddConfigPath(".")
		gViper.SetConfigType("yaml")
		gViper.SetConfigName("config")
	}

	// Set default values
	gViper.SetDefault("email", "admin@example.com")
	gViper.SetDefault("cloudflare:api_token", "")
	gViper.SetDefault("proxies", map[string]interface{}{})

	gViper.AutomaticEnv()

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

	if err := gViper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, create it with default values
			if err := os.MkdirAll(configDir, 0755); err != nil {
				fmt.Fprintf(os.Stderr, "Error creating config directory: %v\n", err)
				os.Exit(1)
			}

			configFile := filepath.Join(configDir, "config.yaml")
			gViper.SetConfigFile(configFile)

			// Set base directory and cert directory in viper config
			gViper.Set("base_dir", configDir)
			gViper.Set("cert_dir", filepath.Join(configDir, "certs"))

			if err := gViper.SafeWriteConfig(); err != nil {
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
	if gViper.GetString("base_dir") == "" {
		gViper.Set("base_dir", configDir)
		gViper.Set("cert_dir", filepath.Join(configDir, "certs"))
		// Save the updated config
		if err := SaveConfig(); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config with base directory: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Using config file: %s\n", gViper.ConfigFileUsed())
	fmt.Printf("Base directory: %s\n", gViper.GetString("base_dir"))

	// Validate required configuration
	if gViper.GetString("cloudflare:api_token") == "" {
		fmt.Fprintf(os.Stderr, "Error: Cloudflare API token not configured. Please set it in the config file.\n")
		os.Exit(1)
	}
}

// SaveConfig saves the current configuration to file
func SaveConfig() error {
	return gViper.WriteConfig()
}

func main() {
	if err := Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
