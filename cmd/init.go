package cmd

import (
	"context"
	"log"

	"github.com/spf13/cobra"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/initalizer"
)

// initCmd represents the initialize command
var initCmd = &cobra.Command{
	Use:   "initialize",
	Short: "Init configures the host, adding a new interface and updating route table",
	Long: `This command creates a new dummy interface and attaches both link-local IPv4 and 
IPv6 (if possible) addresses to interface. It also adds the required entries on the main
route table to route traffic to the new interface.
`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()
		executor, err := initalizer.NewExecutor()
		if err != nil {
			log.Fatalf("Unable to initalize executor %v", err)
		}
		if err := executor.Initialize(ctx); err != nil {
			log.Fatalf("Unable to initalize agent: %v", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
