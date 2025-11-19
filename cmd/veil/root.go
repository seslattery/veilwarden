package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "veil",
	Short: "VeilWarden laptop MITM proxy for AI agents",
	Long: `veil is a CLI wrapper for VeilWarden that provides transparent
API credential injection for AI agents via MITM proxy.

AI agents run through 'veil exec' have zero knowledge of API credentials,
which are fetched from Doppler and injected transparently.`,
	Version: "2.0.0",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// Global flags will be added here
}
