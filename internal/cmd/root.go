package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "dmarcaid",
	Short: "DMARC & TLS-RPT report analyzer",
	Long: `dmarcaid is a CLI tool that parses DMARC aggregate (RUA) and SMTP TLS (TLS-RPT)
reports, providing human-readable analysis with actionable insights.

Supported file types:
  .xml, .xml.gz, .zip    DMARC RUA reports
  .json, .json.gz        TLS-RPT reports

Example:
  dmarcaid parse ./reports
  dmarcaid parse report.xml --detailed
  dmarcaid parse ./reports --format json`,
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
