package cmd

import (
	"sync"

	"github.com/spf13/cobra"
)

var (
	rootCmd = cobra.Command{
		Use: "studio",
	}
	mainWG *sync.WaitGroup
)

func RootCommand(wg *sync.WaitGroup) *cobra.Command {
	mainWG = wg
	rootCmd.AddCommand(&serveCmd)
	return &rootCmd
}
