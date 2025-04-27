package main

import (
	"os"
	"path/filepath"

	"github.com/charmbracelet/log"
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
	// Configure logger
	log.SetReportTimestamp(true)
	log.SetTimeFormat("2006-01-02 15:04:05")

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
			log.Error("Error getting home directory", "err", err)
			os.Exit(1)
		}
		configDir = filepath.Join(home, ".nexo")
	}

	if err := gViper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, create it with default values
			if err := os.MkdirAll(configDir, 0755); err != nil {
				log.Error("Error creating config directory", "err", err)
				os.Exit(1)
			}

			configFile := filepath.Join(configDir, "config.yaml")
			gViper.SetConfigFile(configFile)

			// Set base directory and cert directory in viper config
			gViper.Set("base_dir", configDir)
			gViper.Set("cert_dir", filepath.Join(configDir, "certs"))

			if err := gViper.SafeWriteConfig(); err != nil {
				log.Error("Error creating config file", "err", err)
				os.Exit(1)
			}
			log.Info("Created default config file", "path", configFile)
		} else {
			log.Error("Error reading config file", "err", err)
			os.Exit(1)
		}
	}

	// Ensure base_dir and cert_dir are set even when reading existing config
	if gViper.GetString("base_dir") == "" {
		gViper.Set("base_dir", configDir)
		gViper.Set("cert_dir", filepath.Join(configDir, "certs"))
		// Save the updated config
		if err := SaveConfig(); err != nil {
			log.Error("Error saving config with base directory", "err", err)
			os.Exit(1)
		}
	}

	log.Info("Using config file", "path", gViper.ConfigFileUsed())
	log.Info("Base directory", "path", gViper.GetString("base_dir"))

	// Validate required configuration
	if gViper.GetString("cloudflare:api_token") == "" {
		log.Error("Cloudflare API token not configured. Please set it in the config file.")
		os.Exit(1)
	}
}

// SaveConfig saves the current configuration to file
func SaveConfig() error {
	return gViper.WriteConfig()
}

func main() {
	if err := Execute(); err != nil {
		log.Error("Error executing command", "err", err)
		os.Exit(1)
	}
}
