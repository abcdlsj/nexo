package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/abcdlsj/nexo/internal/server"
	"github.com/abcdlsj/nexo/pkg/config"
	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
)

const (
	defaultConfigPath = "/etc/nexo/config.yaml"
)

var (
	version    = "dev"
	cfgFile    string
	listenAddr string
	adminAddr  string
	logLevel   string

	rootCmd = &cobra.Command{
		Use:   "nexo",
		Short: "A simple HTTPS reverse proxy tool",
		Long: `Nexo is a simple HTTPS reverse proxy tool with automatic certificate management.
It supports wildcard certificates and configuration through YAML files.`,
	}

	serverCmd = &cobra.Command{
		Use:   "server",
		Short: "Run the HTTPS reverse proxy server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfgFile == "" {
				cfgFile = defaultConfigPath
			}

			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

			// Apply flag overrides if provided
			if listenAddr != "" {
				cfg.ListenAddr = listenAddr
			}
			if adminAddr != "" {
				cfg.AdminAddr = adminAddr
			}
			if logLevel != "" {
				cfg.LogLevel = logLevel
			}

			// Configure logger level
			switch cfg.LogLevel {
			case "debug":
				log.SetLevel(log.DebugLevel)
			case "info":
				log.SetLevel(log.InfoLevel)
			case "warn", "warning":
				log.SetLevel(log.WarnLevel)
			case "error":
				log.SetLevel(log.ErrorLevel)
			default:
				log.SetLevel(log.InfoLevel)
			}

			srv, err := server.New(cfg, cfgFile)
			if err != nil {
				return fmt.Errorf("failed to create server: %v", err)
			}

			// Start servers
			go func() {
				if err := srv.StartAdmin(); err != nil {
					log.Error("Admin server exited", "err", err)
				}
			}()

			go func() {
				if err := srv.StartHTTPS(); err != nil {
					log.Error("HTTPS server exited", "err", err)
				}
			}()

			// Graceful shutdown on signals
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			<-sigCh

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return srv.Shutdown(ctx)
		},
	}

	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version)
		},
	}
)

func init() {
	// Configure logger
	log.SetReportTimestamp(true)
	log.SetTimeFormat("2006-01-02 15:04:05")

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is /etc/nexo/config.yaml)")
	serverCmd.Flags().StringVar(&listenAddr, "listen-addr", "", "HTTPS listen address (overrides config)")
	serverCmd.Flags().StringVar(&adminAddr, "admin-addr", "", "Admin HTTP listen address for health checks (overrides config)")
	serverCmd.Flags().StringVar(&logLevel, "log-level", "", "Log level: debug|info|warn|error (overrides config)")

	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal("Error executing command", "err", err)
		os.Exit(1)
	}
}
