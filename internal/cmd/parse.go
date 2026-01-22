package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/kidager/dmarcaid/internal/analysis"
	"github.com/kidager/dmarcaid/internal/output"
	"github.com/kidager/dmarcaid/internal/parser"
	"github.com/kidager/dmarcaid/pkg/types"
)

var (
	detailed     bool
	outputJSON   bool
	showInsights bool
	filterDomain string
	filterStatus string
	filterIP     string
)

var parseCmd = &cobra.Command{
	Use:   "parse [files or directories...]",
	Short: "Parse DMARC and TLS-RPT report files",
	Long: `Parse one or more report files or directories containing reports.

Results are aggregated by domain across all input files.

Examples:
  dmarcaid parse report.xml
  dmarcaid parse ./reports/
  dmarcaid parse report1.xml report2.xml.gz ./more-reports/
  dmarcaid parse ./reports --detailed
  dmarcaid parse ./reports --json
  dmarcaid parse ./reports --domain example.com`,
	Args: cobra.MinimumNArgs(1),
	RunE: runParse,
}

func init() {
	rootCmd.AddCommand(parseCmd)

	parseCmd.Flags().BoolVarP(&detailed, "detailed", "d", false, "Show detailed output with all records")
	parseCmd.Flags().BoolVarP(&showInsights, "insights", "i", true, "Show insights and recommendations")
	parseCmd.Flags().BoolVar(&outputJSON, "json", false, "Output results as JSON")
	parseCmd.Flags().StringVar(&filterDomain, "domain", "", "Filter results by domain")
	parseCmd.Flags().StringVar(&filterStatus, "status", "", "Filter by status (pass, fail)")
	parseCmd.Flags().StringVar(&filterIP, "ip", "", "Filter by source IP")
}

func runParse(_ *cobra.Command, args []string) error {
	// Collect all files to parse
	var files []string
	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			return fmt.Errorf("accessing %s: %w", arg, err)
		}

		if info.IsDir() {
			dirFiles, err := parser.WalkDirectory(arg)
			if err != nil {
				return fmt.Errorf("walking directory %s: %w", arg, err)
			}
			files = append(files, dirFiles...)
		} else {
			files = append(files, arg)
		}
	}

	if len(files) == 0 {
		return fmt.Errorf("no report files found")
	}

	// Parse all files
	result := parseFiles(files)

	// Aggregate by domain
	aggregated := analysis.Aggregate(result)

	// Generate insights
	var insights *analysis.InsightsResult
	if showInsights {
		insights = analysis.GenerateInsights(aggregated)
	}

	// Convert back to ParseResult format (now aggregated)
	aggregatedResult := aggregated.ToParseResult()
	aggregatedResult.Errors = result.Errors

	// Apply filters
	aggregatedResult = applyFilters(aggregatedResult)

	// Output results
	if outputJSON {
		return outputResultsJSON(aggregatedResult, insights, detailed)
	}
	return outputResultsTable(aggregatedResult, insights, detailed)
}

func parseFiles(files []string) *types.ParseResult {
	result := &types.ParseResult{}

	for _, file := range files {
		dmarc, tls, forensic, err := parser.ParseFile(file)
		if err != nil {
			result.Errors = append(result.Errors, types.ParseError{
				File:  filepath.Base(file),
				Error: err.Error(),
			})
			continue
		}

		result.FilesParsed++

		if dmarc != nil {
			result.DMARCReports = append(result.DMARCReports, *dmarc)
			result.DMARCFiles++
		}
		if tls != nil {
			result.TLSReports = append(result.TLSReports, *tls)
			result.TLSFiles++
		}
		if forensic != nil {
			result.ForensicReports = append(result.ForensicReports, *forensic)
			result.ForensicFiles++
		}
	}

	return result
}

func applyFilters(result *types.ParseResult) *types.ParseResult {
	if filterDomain == "" && filterStatus == "" && filterIP == "" {
		return result
	}

	filtered := &types.ParseResult{
		FilesParsed: result.FilesParsed,
		Errors:      result.Errors,
	}

	// Filter DMARC reports
	for _, report := range result.DMARCReports {
		if filterDomain != "" && report.Domain != filterDomain {
			continue
		}
		if filterStatus != "" {
			if filterStatus == "pass" && report.Fail > 0 {
				continue
			}
			if filterStatus == "fail" && report.Fail == 0 {
				continue
			}
		}
		if filterIP != "" {
			hasIP := false
			for _, src := range report.Sources {
				if src.IP == filterIP {
					hasIP = true
					break
				}
			}
			if !hasIP {
				continue
			}
		}
		filtered.DMARCReports = append(filtered.DMARCReports, report)
		filtered.DMARCFiles++
	}

	// Filter TLS reports
	for _, report := range result.TLSReports {
		if filterDomain != "" && report.Domain != filterDomain {
			continue
		}
		if filterStatus != "" {
			if filterStatus == "pass" && report.Failure > 0 {
				continue
			}
			if filterStatus == "fail" && report.Failure == 0 {
				continue
			}
		}
		filtered.TLSReports = append(filtered.TLSReports, report)
		filtered.TLSFiles++
	}

	return filtered
}

func outputResultsTable(result *types.ParseResult, insights *analysis.InsightsResult, detailed bool) error {
	fmt.Print(output.TableOutput(result, detailed))
	if insights != nil && len(insights.Insights) > 0 {
		fmt.Print(output.InsightsOutput(insights, detailed))
	}
	return nil
}

func outputResultsJSON(result *types.ParseResult, insights *analysis.InsightsResult, detailed bool) error {
	jsonStr, err := output.ToJSONWithInsights(result, insights, detailed)
	if err != nil {
		return fmt.Errorf("generating JSON: %w", err)
	}
	fmt.Println(jsonStr)
	return nil
}
