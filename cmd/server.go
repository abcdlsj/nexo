package cmd

import (
	"github.com/abcdlsj/nexo/internal/server"
	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the Nexo server",
	Long:  `Start the Nexo HTTPS reverse proxy server with automatic certificate management.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		s := server.New()
		return s.Start()
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
}
