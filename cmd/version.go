/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
        "go.amzn.com/eks/eks-pod-identity-agent/configuration"
)

var AgentVersion string = "v0.1.32"

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Prints agent version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("EKS Pod Identity Agent version %s\n",configuration.AgentVersion)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
