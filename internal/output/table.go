// Package output provides formatted output for report data.
package output

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/kidager/dmarcaid/internal/analysis"
	"github.com/kidager/dmarcaid/pkg/types"
)

// Styles for terminal output.
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("12")).
			MarginBottom(1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("240")).
			Padding(0, 1)

	cellStyle = lipgloss.NewStyle().
			Padding(0, 1)

	passStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("10"))

	failStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("9"))

	warnStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("11"))

	mutedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")).
			Bold(true)

	sectionStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("14")).
			MarginTop(1).
			MarginBottom(1)

	criticalStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("9"))

	warningStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("11"))

	infoStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("12"))

	insightTitleStyle = lipgloss.NewStyle().
				Bold(true)

	insightDescStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("250"))

	suggestionStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("250")).
			Italic(true)
)

// TableOutput renders parse results as styled terminal output.
func TableOutput(result *types.ParseResult, detailed bool) string {
	var sb strings.Builder

	// Summary header
	sb.WriteString(titleStyle.Render("DMARC Report Analysis"))
	sb.WriteString("\n\n")

	// File summary
	fileSummary := fmt.Sprintf("Parsed %d files: %s DMARC, %s TLS-RPT, %s Forensic",
		result.FilesParsed,
		passStyle.Render(fmt.Sprintf("%d", result.DMARCFiles)),
		passStyle.Render(fmt.Sprintf("%d", result.TLSFiles)),
		passStyle.Render(fmt.Sprintf("%d", result.ForensicFiles)))
	sb.WriteString(fileSummary)
	sb.WriteString("\n")

	// Errors section
	if len(result.Errors) > 0 {
		sb.WriteString("\n")
		sb.WriteString(errorStyle.Render(fmt.Sprintf("Errors (%d):", len(result.Errors))))
		sb.WriteString("\n")
		for _, e := range result.Errors {
			sb.WriteString(fmt.Sprintf("  %s %s\n",
				mutedStyle.Render(e.File+":"),
				failStyle.Render(e.Error)))
		}
	}

	// DMARC Reports
	if len(result.DMARCReports) > 0 {
		sb.WriteString("\n")
		sb.WriteString(sectionStyle.Render("DMARC Reports"))
		sb.WriteString("\n")
		sb.WriteString(renderDMARCTable(result.DMARCReports, detailed))
	}

	// TLS-RPT Reports
	if len(result.TLSReports) > 0 {
		sb.WriteString("\n")
		sb.WriteString(sectionStyle.Render("TLS-RPT Reports"))
		sb.WriteString("\n")
		sb.WriteString(renderTLSTable(result.TLSReports, detailed))
	}

	// Forensic Reports
	if len(result.ForensicReports) > 0 {
		sb.WriteString("\n")
		sb.WriteString(sectionStyle.Render("Forensic Reports (DMARC Failures)"))
		sb.WriteString("\n")
		sb.WriteString(renderForensicTable(result.ForensicReports, detailed))
	}

	return sb.String()
}

func renderDMARCTable(reports []types.DMARCReport, detailed bool) string {
	var sb strings.Builder

	// Table header
	headers := []string{"Domain", "Messages", "Pass", "Fail", "Rate", "Reporters"}
	sb.WriteString(renderTableRow(headers, true))
	sb.WriteString("\n")

	// Table rows
	for _, r := range reports {
		rate := 100.0
		if r.TotalMessages > 0 {
			rate = float64(r.Pass) / float64(r.TotalMessages) * 100
		}

		rateStr := formatRate(rate)
		reporters := strings.Join(r.Reporters, ", ")
		if len(reporters) > 30 {
			reporters = reporters[:27] + "..."
		}

		row := []string{
			r.Domain,
			fmt.Sprintf("%d", r.TotalMessages),
			passStyle.Render(fmt.Sprintf("%d", r.Pass)),
			formatFailCount(r.Fail),
			rateStr,
			mutedStyle.Render(reporters),
		}
		sb.WriteString(renderTableRow(row, false))
		sb.WriteString("\n")

		if detailed {
			sb.WriteString(renderDMARCDetails(r))
		}
	}

	return sb.String()
}

func renderDMARCDetails(r types.DMARCReport) string {
	var sb strings.Builder

	// Authentication breakdown
	sb.WriteString(mutedStyle.Render("    Auth: "))
	sb.WriteString(fmt.Sprintf("SPF+DKIM=%d  DKIM-only=%d  SPF-only=%d  Neither=%d\n",
		r.Breakdown.SPFAndDKIM, r.Breakdown.DKIMOnly, r.Breakdown.SPFOnly, r.Breakdown.Neither))

	// Policy stats
	sb.WriteString(mutedStyle.Render("    Policy: "))
	sb.WriteString(fmt.Sprintf("none=%d  quarantine=%d  reject=%d\n",
		r.PolicyApplied.None, r.PolicyApplied.Quarantine, r.PolicyApplied.Reject))

	// Sources
	if len(r.Sources) > 0 {
		sb.WriteString(mutedStyle.Render("    Sources:"))
		sb.WriteString("\n")
		for _, src := range r.Sources {
			sb.WriteString(fmt.Sprintf("      %-40s %d msgs, SPF=%s, DKIM=%s\n",
				src.IP, src.Count, src.SPFResult, src.DKIMResult))
		}
	}

	// Failures
	if len(r.Failures) > 0 {
		sb.WriteString(failStyle.Render("    Failures:"))
		sb.WriteString("\n")
		for _, f := range r.Failures {
			sb.WriteString(fmt.Sprintf("      %-30s %d msgs from %-40s SPF=%s, DKIM=%s\n",
				f.HeaderFrom, f.Count, f.SourceIP, f.SPFResult, f.DKIMResult))
		}
	}

	sb.WriteString("\n")
	return sb.String()
}

func renderTLSTable(reports []types.TLSReport, detailed bool) string {
	var sb strings.Builder

	// Table header
	headers := []string{"Domain", "Sessions", "Success", "Failure", "Rate", "Reporters"}
	sb.WriteString(renderTableRow(headers, true))
	sb.WriteString("\n")

	// Table rows
	for _, r := range reports {
		rate := 100.0
		if r.TotalSessions > 0 {
			rate = float64(r.Success) / float64(r.TotalSessions) * 100
		}

		rateStr := formatRate(rate)
		reporters := strings.Join(r.Reporters, ", ")
		if len(reporters) > 30 {
			reporters = reporters[:27] + "..."
		}

		row := []string{
			r.Domain,
			fmt.Sprintf("%d", r.TotalSessions),
			passStyle.Render(fmt.Sprintf("%d", r.Success)),
			formatFailCount(r.Failure),
			rateStr,
			mutedStyle.Render(reporters),
		}
		sb.WriteString(renderTableRow(row, false))
		sb.WriteString("\n")

		if detailed && len(r.Failures) > 0 {
			sb.WriteString(renderTLSDetails(r))
		}
	}

	return sb.String()
}

func renderTLSDetails(r types.TLSReport) string {
	var sb strings.Builder

	sb.WriteString(failStyle.Render("    Failures:"))
	sb.WriteString("\n")
	for _, f := range r.Failures {
		sb.WriteString(fmt.Sprintf("      %-30s %d sessions (%s -> %s)\n",
			f.Type, f.Count, f.SendingMTA, f.ReceivingMTA))
	}

	sb.WriteString("\n")
	return sb.String()
}

func renderForensicTable(reports []types.ForensicReport, detailed bool) string {
	var sb strings.Builder

	// Table header
	headers := []string{"Domain", "Source IP", "SPF", "DKIM", "DMARC", "Reporter"}
	sb.WriteString(renderTableRow(headers, true))
	sb.WriteString("\n")

	// Table rows
	for _, r := range reports {
		reporter := ""
		if len(r.Reporters) > 0 {
			reporter = r.Reporters[0]
		}
		if len(reporter) > 30 {
			reporter = reporter[:27] + "..."
		}

		row := []string{
			r.Domain,
			r.SourceIP,
			formatAuthResult(r.SPFResult),
			formatAuthResult(r.DKIMResult),
			formatAuthResult(r.DMARCResult),
			mutedStyle.Render(reporter),
		}
		sb.WriteString(renderTableRow(row, false))
		sb.WriteString("\n")

		if detailed {
			sb.WriteString(renderForensicDetails(r))
		}
	}

	return sb.String()
}

func renderForensicDetails(r types.ForensicReport) string {
	var sb strings.Builder

	// Basic info
	sb.WriteString(mutedStyle.Render("    Arrival: "))
	if !r.ArrivalDate.IsZero() {
		sb.WriteString(r.ArrivalDate.Format("2006-01-02 15:04:05"))
	} else {
		sb.WriteString("unknown")
	}
	sb.WriteString("\n")

	// Mail info
	if r.OriginalMailFrom != "" {
		sb.WriteString(mutedStyle.Render("    From: "))
		sb.WriteString(r.OriginalMailFrom)
		sb.WriteString("\n")
	}
	if r.OriginalRcptTo != "" {
		sb.WriteString(mutedStyle.Render("    To: "))
		sb.WriteString(r.OriginalRcptTo)
		sb.WriteString("\n")
	}
	if r.Subject != "" {
		subject := r.Subject
		if len(subject) > 60 {
			subject = subject[:57] + "..."
		}
		sb.WriteString(mutedStyle.Render("    Subject: "))
		sb.WriteString(subject)
		sb.WriteString("\n")
	}

	// DKIM info
	if r.DKIMDomain != "" || r.DKIMSelector != "" {
		sb.WriteString(mutedStyle.Render("    DKIM: "))
		if r.DKIMDomain != "" {
			sb.WriteString(fmt.Sprintf("domain=%s", r.DKIMDomain))
		}
		if r.DKIMSelector != "" {
			if r.DKIMDomain != "" {
				sb.WriteString(", ")
			}
			sb.WriteString(fmt.Sprintf("selector=%s", r.DKIMSelector))
		}
		sb.WriteString("\n")
	}

	// Delivery result
	if r.DeliveryResult != "" {
		sb.WriteString(mutedStyle.Render("    Delivery: "))
		sb.WriteString(r.DeliveryResult)
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	return sb.String()
}

func formatAuthResult(result string) string {
	result = strings.ToLower(result)
	switch result {
	case "pass":
		return passStyle.Render("pass")
	case "fail", "failed":
		return failStyle.Render("fail")
	case "softfail":
		return warnStyle.Render("softfail")
	case "neutral", "none", "":
		return mutedStyle.Render(result)
	default:
		return result
	}
}

func renderTableRow(cells []string, isHeader bool) string {
	widths := []int{25, 10, 8, 8, 8, 35}
	var parts []string

	for i, cell := range cells {
		width := widths[i]
		if i >= len(widths) {
			width = 15
		}

		// Use lipgloss.Width to get visual width (ignores ANSI codes)
		visualWidth := lipgloss.Width(cell)

		padded := cell
		if visualWidth < width {
			padded = cell + strings.Repeat(" ", width-visualWidth)
		} else if visualWidth > width {
			// For truncation, we need to strip ANSI, truncate, then indicate truncation
			stripped := stripANSI(cell)
			if len(stripped) > width-3 {
				padded = stripped[:width-3] + "..."
			}
		}

		if isHeader {
			parts = append(parts, headerStyle.Render(padded))
		} else {
			parts = append(parts, cellStyle.Render(padded))
		}
	}

	return strings.Join(parts, "")
}

// stripANSI removes ANSI escape sequences from a string
func stripANSI(s string) string {
	var result strings.Builder
	inEscape := false
	for _, r := range s {
		if r == '\x1b' {
			inEscape = true
			continue
		}
		if inEscape {
			if r == 'm' {
				inEscape = false
			}
			continue
		}
		result.WriteRune(r)
	}
	return result.String()
}

func formatRate(rate float64) string {
	rateStr := fmt.Sprintf("%.1f%%", rate)
	if rate >= 99 {
		return passStyle.Render(rateStr)
	} else if rate >= 90 {
		return warnStyle.Render(rateStr)
	}
	return failStyle.Render(rateStr)
}

func formatFailCount(count int) string {
	if count == 0 {
		return mutedStyle.Render("0")
	}
	return failStyle.Render(fmt.Sprintf("%d", count))
}

// InsightsOutput renders insights as styled terminal output.
func InsightsOutput(insights *analysis.InsightsResult, detailed bool) string {
	if len(insights.Insights) == 0 {
		return ""
	}

	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString(sectionStyle.Render("Insights"))
	sb.WriteString("\n\n")

	// Summary
	summaryParts := []string{}
	if insights.CriticalCount > 0 {
		summaryParts = append(summaryParts, criticalStyle.Render(fmt.Sprintf("%d critical", insights.CriticalCount)))
	}
	if insights.WarningCount > 0 {
		summaryParts = append(summaryParts, warningStyle.Render(fmt.Sprintf("%d warnings", insights.WarningCount)))
	}
	if insights.InfoCount > 0 {
		summaryParts = append(summaryParts, infoStyle.Render(fmt.Sprintf("%d info", insights.InfoCount)))
	}
	sb.WriteString(fmt.Sprintf("Found %s", strings.Join(summaryParts, ", ")))

	if !detailed {
		sb.WriteString(mutedStyle.Render("  (use --detailed for recommendations)"))
		sb.WriteString("\n")
		return sb.String()
	}

	sb.WriteString("\n\n")

	// Show details
	for _, insight := range insights.Insights {
		sb.WriteString(renderInsight(insight))
	}

	return sb.String()
}

func renderInsight(i analysis.Insight) string {
	var sb strings.Builder

	// Severity indicator
	var severityIndicator string
	switch i.Severity {
	case analysis.SeverityCritical:
		severityIndicator = criticalStyle.Render("[CRITICAL]")
	case analysis.SeverityWarning:
		severityIndicator = warningStyle.Render("[WARNING]")
	case analysis.SeverityInfo:
		severityIndicator = infoStyle.Render("[INFO]")
	}

	// Domain if present
	domain := ""
	if i.Domain != "" {
		domain = mutedStyle.Render(fmt.Sprintf(" (%s)", i.Domain))
	}

	sb.WriteString(fmt.Sprintf("%s %s%s\n", severityIndicator, insightTitleStyle.Render(i.Title), domain))
	sb.WriteString(fmt.Sprintf("  %s\n", insightDescStyle.Render(i.Description)))

	if i.Suggestion != "" {
		sb.WriteString(fmt.Sprintf("  %s %s\n", mutedStyle.Render("->"), suggestionStyle.Render(i.Suggestion)))
	}

	sb.WriteString("\n")
	return sb.String()
}
