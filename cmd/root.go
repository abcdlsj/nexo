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
It supports wildcard certificates and provides a simple command-line interface for proxy management.`,
	}
)

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.nexo/config.yaml)")
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		configDir := filepath.Join(home, ".nexo")
		if err := os.MkdirAll(configDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating config directory: %v\n", err)
			os.Exit(1)
		}

		viper.AddConfigPath(configDir)
		viper.SetConfigType("yaml")
		viper.SetConfigName("config")
	}

	// Set default values
	viper.SetDefault("email", "admin@example.com")
	viper.SetDefault("cloudflare.api_token", "")
	viper.SetDefault("proxies", map[string]interface{}{})

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, create it with default values
			if err := viper.SafeWriteConfig(); err != nil {
				fmt.Fprintf(os.Stderr, "Error creating config file: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Error reading config file: %v\n", err)
			os.Exit(1)
		}
	}

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
