package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
)

var loggingVerbosity string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "eks-pod-identity-agent",
	Short: "The agent contains a proxy server and its initializer, for more information look at the server command",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logger.Initialize(loggingVerbosity)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&loggingVerbosity, "verbosity", "v", "info", "Logging verbosity can be one of: panic, error, info, trace")
}
