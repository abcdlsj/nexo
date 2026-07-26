package main

import (
	"fmt"
	"os"

	"github.com/abcdlsj/nexo/internal/server"
	"github.com/abcdlsj/nexo/internal/webui"
	"github.com/abcdlsj/nexo/pkg/config"
	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
)

const (
	defaultConfigPath = "/etc/nexo/config.yaml"
)

var (
	cfgFile     string
	previewAddr string
	rootCmd     = &cobra.Command{
		Use:   "nexo",
		Short: "A simple HTTPS reverse proxy tool",
		Long: `Nexo is a simple HTTPS reverse proxy tool with automatic certificate management.
It supports wildcard certificates and configuration through YAML files.`,
		Args: cobra.NoArgs,
		RunE: runServer,
	}
	serverCmd = &cobra.Command{
		Use:   "server",
		Short: "Start the HTTPS proxy and management UI",
		Args:  cobra.NoArgs,
		RunE:  runServer,
	}
	previewCmd = &cobra.Command{
		Use:   "preview",
		Short: "Preview the WebUI locally with fake data",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Info("Starting fake-data WebUI preview", "addr", previewAddr)
			return webui.StartPreview(previewAddr)
		},
	}
)

func runServer(cmd *cobra.Command, args []string) error {
	if cfgFile == "" {
		cfgFile = defaultConfigPath
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}
	srv, err := server.New(cfg, cfgFile)
	if err != nil {
		return fmt.Errorf("failed to create server: %v", err)
	}
	return srv.Start()
}

func init() {
	// Configure logger
	log.SetReportTimestamp(true)
	log.SetTimeFormat("2006-01-02 15:04:05")

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is /etc/nexo/config.yaml)")
	previewCmd.Flags().StringVar(&previewAddr, "addr", "127.0.0.1:8088", "loopback address for the preview server")
	rootCmd.AddCommand(serverCmd, previewCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal("Error executing command", "err", err)
		os.Exit(1)
	}
}
