package main

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// buildVersion is set at link time: -ldflags "-X main.buildVersion=v1.2.3".
var buildVersion = ""

func version() string {
	if buildVersion != "" {
		return buildVersion
	}

	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				return s.Value
			}
		}
	}

	return "dev"
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the build version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), version())
			return err
		},
	}
}
