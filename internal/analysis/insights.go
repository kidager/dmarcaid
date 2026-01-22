package analysis

import (
	"fmt"
	"sort"
)

// Severity represents the severity level of an insight.
type Severity int

// Insight severity levels.
const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarning:
		return "warning"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Category represents the category of an insight.
type Category string

// Insight categories.
const (
	CategoryDKIM      Category = "dkim"
	CategorySPF       Category = "spf"
	CategoryAlignment Category = "alignment"
	CategoryPolicy    Category = "policy"
	CategoryTLS       Category = "tls"
	CategorySource    Category = "source"
	CategoryForensic  Category = "forensic"
)

// Insight represents a recommendation or finding from the analysis.
type Insight struct {
	Severity    Severity `json:"severity"`
	Category    Category `json:"category"`
	Domain      string   `json:"domain,omitempty"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Suggestion  string   `json:"suggestion,omitempty"`
}

// InsightsResult contains all insights from the analysis.
type InsightsResult struct {
	Insights      []Insight `json:"insights"`
	CriticalCount int       `json:"critical_count"`
	WarningCount  int       `json:"warning_count"`
	InfoCount     int       `json:"info_count"`
}

// GenerateInsights analyzes aggregated results and generates insights.
func GenerateInsights(agg *AggregatedResult) *InsightsResult {
	result := &InsightsResult{}

	// Analyze each DMARC domain
	for domain, d := range agg.DMARC {
		analyzeDMARCDomain(result, domain, d)
	}

	// Analyze each TLS domain
	for domain, t := range agg.TLSRPT {
		analyzeTLSDomain(result, domain, t)
	}

	// Analyze each forensic domain
	for domain, f := range agg.Forensic {
		analyzeForensicDomain(result, domain, f)
	}

	// Generate overall insights
	analyzeOverall(result, agg)

	// Sort by severity (critical first)
	sort.Slice(result.Insights, func(i, j int) bool {
		if result.Insights[i].Severity != result.Insights[j].Severity {
			return result.Insights[i].Severity > result.Insights[j].Severity
		}
		return result.Insights[i].Domain < result.Insights[j].Domain
	})

	// Count by severity
	for _, insight := range result.Insights {
		switch insight.Severity {
		case SeverityCritical:
			result.CriticalCount++
		case SeverityWarning:
			result.WarningCount++
		case SeverityInfo:
			result.InfoCount++
		}
	}

	return result
}

func analyzeDMARCDomain(result *InsightsResult, domain string, d *AggregatedDMARC) {
	// Check pass rate
	if d.TotalMessages > 0 {
		if d.PassRate < 90 {
			result.addInsight(Insight{
				Severity:    SeverityCritical,
				Category:    CategoryAlignment,
				Domain:      domain,
				Title:       "Low DMARC pass rate",
				Description: fmt.Sprintf("Only %.1f%% of messages passed DMARC (threshold: 90%%)", d.PassRate),
				Suggestion:  "Review SPF and DKIM configuration for this domain",
			})
		} else if d.PassRate < 99 {
			result.addInsight(Insight{
				Severity:    SeverityWarning,
				Category:    CategoryAlignment,
				Domain:      domain,
				Title:       "DMARC pass rate below optimal",
				Description: fmt.Sprintf("%.1f%% of messages passed DMARC (target: 99%%+)", d.PassRate),
				Suggestion:  "Investigate sources causing failures",
			})
		}
	}

	// Check DKIM alignment
	if d.DKIM.Pass > 0 && d.DKIM.Aligned < d.DKIM.Pass {
		alignRate := float64(d.DKIM.Aligned) / float64(d.DKIM.Pass) * 100
		if alignRate < 90 {
			result.addInsight(Insight{
				Severity:    SeverityWarning,
				Category:    CategoryDKIM,
				Domain:      domain,
				Title:       "Low DKIM alignment",
				Description: fmt.Sprintf("Only %.1f%% of DKIM-passing messages are aligned", alignRate),
				Suggestion:  "Ensure DKIM signatures use the same domain as the From header",
			})
		}
	}

	// Check SPF alignment
	if d.SPF.Pass > 0 && d.SPF.Aligned < d.SPF.Pass {
		alignRate := float64(d.SPF.Aligned) / float64(d.SPF.Pass) * 100
		if alignRate < 90 {
			result.addInsight(Insight{
				Severity:    SeverityWarning,
				Category:    CategorySPF,
				Domain:      domain,
				Title:       "Low SPF alignment",
				Description: fmt.Sprintf("Only %.1f%% of SPF-passing messages are aligned", alignRate),
				Suggestion:  "Ensure envelope From domain matches header From domain",
			})
		}
	}

	// Check for DKIM failures
	if d.DKIM.Fail > 0 {
		failRate := float64(d.DKIM.Fail) / float64(d.DKIM.Pass+d.DKIM.Fail) * 100
		if failRate > 10 {
			result.addInsight(Insight{
				Severity:    SeverityWarning,
				Category:    CategoryDKIM,
				Domain:      domain,
				Title:       "DKIM failures detected",
				Description: fmt.Sprintf("%.1f%% of messages have DKIM failures (%d messages)", failRate, d.DKIM.Fail),
				Suggestion:  "Check DKIM key rotation and DNS records",
			})
		}
	}

	// Check for SPF failures
	if d.SPF.Fail > 0 || d.SPF.SoftFail > 0 {
		totalFails := d.SPF.Fail + d.SPF.SoftFail
		totalSPF := d.SPF.Pass + d.SPF.Fail + d.SPF.SoftFail + d.SPF.Neutral
		if totalSPF > 0 {
			failRate := float64(totalFails) / float64(totalSPF) * 100
			if failRate > 10 {
				result.addInsight(Insight{
					Severity:    SeverityWarning,
					Category:    CategorySPF,
					Domain:      domain,
					Title:       "SPF failures detected",
					Description: fmt.Sprintf("%.1f%% of messages have SPF failures (%d messages)", failRate, totalFails),
					Suggestion:  "Review SPF record and authorized senders",
				})
			}
		}
	}

	// Check policy disposition
	if d.PolicyApplied.Reject > 0 {
		result.addInsight(Insight{
			Severity:    SeverityInfo,
			Category:    CategoryPolicy,
			Domain:      domain,
			Title:       "Messages rejected by policy",
			Description: fmt.Sprintf("%d messages were rejected due to DMARC policy", d.PolicyApplied.Reject),
			Suggestion:  "Review rejected sources if unexpected",
		})
	}

	if d.PolicyApplied.Quarantine > 0 {
		result.addInsight(Insight{
			Severity:    SeverityInfo,
			Category:    CategoryPolicy,
			Domain:      domain,
			Title:       "Messages quarantined by policy",
			Description: fmt.Sprintf("%d messages were quarantined due to DMARC policy", d.PolicyApplied.Quarantine),
			Suggestion:  "Review quarantined sources if unexpected",
		})
	}

	// Check for neither SPF nor DKIM passing
	if d.Breakdown.Neither > 0 {
		result.addInsight(Insight{
			Severity:    SeverityCritical,
			Category:    CategoryAlignment,
			Domain:      domain,
			Title:       "Messages failing both SPF and DKIM",
			Description: fmt.Sprintf("%d messages failed both SPF and DKIM authentication", d.Breakdown.Neither),
			Suggestion:  "These messages are likely spoofed or from misconfigured sources",
		})
	}

	// Check for suspicious sources
	for _, src := range d.SourcesList {
		if src.PassRate < 50 && src.Count >= 5 {
			result.addInsight(Insight{
				Severity:    SeverityWarning,
				Category:    CategorySource,
				Domain:      domain,
				Title:       "Low pass rate from source",
				Description: fmt.Sprintf("IP %s has only %.1f%% pass rate (%d messages)", src.IP, src.PassRate, src.Count),
				Suggestion:  "Investigate if this is a legitimate sender",
			})
		}
	}

	// Check failures
	if len(d.Failures) > 0 {
		failedDomains := make(map[string]int)
		for _, f := range d.Failures {
			failedDomains[f.HeaderFrom] += f.Count
		}
		for failDomain, count := range failedDomains {
			if failDomain != domain && count >= 3 {
				result.addInsight(Insight{
					Severity:    SeverityWarning,
					Category:    CategoryAlignment,
					Domain:      domain,
					Title:       "Failures from different header domain",
					Description: fmt.Sprintf("%d failures with From: %s (possible spoofing attempt)", count, failDomain),
					Suggestion:  "Monitor this pattern for potential abuse",
				})
			}
		}
	}
}

func analyzeTLSDomain(result *InsightsResult, domain string, t *AggregatedTLS) {
	// Check success rate
	if t.TotalSessions > 0 {
		if t.SuccessRate < 90 {
			result.addInsight(Insight{
				Severity:    SeverityCritical,
				Category:    CategoryTLS,
				Domain:      domain,
				Title:       "Low TLS success rate",
				Description: fmt.Sprintf("Only %.1f%% of TLS sessions succeeded (threshold: 90%%)", t.SuccessRate),
				Suggestion:  "Check MTA-STS policy and certificate configuration",
			})
		} else if t.SuccessRate < 99 {
			result.addInsight(Insight{
				Severity:    SeverityWarning,
				Category:    CategoryTLS,
				Domain:      domain,
				Title:       "TLS success rate below optimal",
				Description: fmt.Sprintf("%.1f%% of TLS sessions succeeded (target: 99%%+)", t.SuccessRate),
				Suggestion:  "Review TLS configuration and certificate chain",
			})
		}
	}

	// Check for specific failure types
	for failType, count := range t.FailureTypes {
		severity := SeverityWarning
		suggestion := ""

		switch failType {
		case "certificate-expired":
			severity = SeverityCritical
			suggestion = "Renew the expired certificate immediately"
		case "certificate-not-trusted":
			severity = SeverityCritical
			suggestion = "Use a certificate from a trusted CA"
		case "certificate-host-mismatch":
			severity = SeverityCritical
			suggestion = "Ensure certificate matches the mail server hostname"
		case "starttls-not-supported":
			suggestion = "Enable STARTTLS on the mail server"
		case "validation-failure":
			suggestion = "Review MTA-STS policy configuration"
		case "sts-policy-invalid":
			suggestion = "Fix the MTA-STS policy syntax"
		case "sts-webpki-invalid":
			suggestion = "Ensure valid certificate chain for HTTPS"
		default:
			suggestion = "Investigate the failure cause"
		}

		result.addInsight(Insight{
			Severity:    severity,
			Category:    CategoryTLS,
			Domain:      domain,
			Title:       fmt.Sprintf("TLS failure: %s", failType),
			Description: fmt.Sprintf("%d sessions failed with %s", count, failType),
			Suggestion:  suggestion,
		})
	}
}

func analyzeForensicDomain(result *InsightsResult, domain string, f *AggregatedForensic) {
	// High volume of forensic reports indicates active attacks or misconfigurations
	if f.ReportCount >= 10 {
		result.addInsight(Insight{
			Severity:    SeverityCritical,
			Category:    CategoryForensic,
			Domain:      domain,
			Title:       "High volume of forensic reports",
			Description: fmt.Sprintf("%d DMARC failure reports received for this domain", f.ReportCount),
			Suggestion:  "Review authentication configuration and check for spoofing attempts",
		})
	} else if f.ReportCount >= 3 {
		result.addInsight(Insight{
			Severity:    SeverityWarning,
			Category:    CategoryForensic,
			Domain:      domain,
			Title:       "Multiple forensic reports received",
			Description: fmt.Sprintf("%d DMARC failure reports received for this domain", f.ReportCount),
			Suggestion:  "Investigate the source of authentication failures",
		})
	}

	// Check for DKIM failures
	if f.DKIMFail > 0 {
		result.addInsight(Insight{
			Severity:    SeverityWarning,
			Category:    CategoryDKIM,
			Domain:      domain,
			Title:       "DKIM failures in forensic reports",
			Description: fmt.Sprintf("%d forensic reports show DKIM failures", f.DKIMFail),
			Suggestion:  "Verify DKIM signing configuration and DNS records",
		})
	}

	// Check for SPF failures
	if f.SPFFail > 0 {
		result.addInsight(Insight{
			Severity:    SeverityWarning,
			Category:    CategorySPF,
			Domain:      domain,
			Title:       "SPF failures in forensic reports",
			Description: fmt.Sprintf("%d forensic reports show SPF failures", f.SPFFail),
			Suggestion:  "Review authorized senders in SPF record",
		})
	}

	// Check for multiple source IPs
	if len(f.SourceIPs) > 5 {
		result.addInsight(Insight{
			Severity:    SeverityWarning,
			Category:    CategorySource,
			Domain:      domain,
			Title:       "Multiple IPs sending failed messages",
			Description: fmt.Sprintf("Failures reported from %d different source IPs", len(f.SourceIPs)),
			Suggestion:  "This may indicate a spoofing campaign or unauthorized senders",
		})
	}

	// Check for concentrated failures from single IP
	for ip, count := range f.SourceIPs {
		if count >= 5 {
			result.addInsight(Insight{
				Severity:    SeverityWarning,
				Category:    CategorySource,
				Domain:      domain,
				Title:       "Repeated failures from single IP",
				Description: fmt.Sprintf("IP %s has caused %d authentication failures", ip, count),
				Suggestion:  "Investigate if this IP is an authorized sender or potential attacker",
			})
		}
	}
}

func analyzeOverall(result *InsightsResult, agg *AggregatedResult) {
	// Check overall DMARC pass rate
	if agg.Summary.TotalMessages > 100 && agg.Summary.OverallPassRate >= 99 {
		result.addInsight(Insight{
			Severity:    SeverityInfo,
			Category:    CategoryAlignment,
			Title:       "Excellent DMARC compliance",
			Description: fmt.Sprintf("Overall %.1f%% pass rate across %d messages", agg.Summary.OverallPassRate, agg.Summary.TotalMessages),
		})
	}

	// Check overall TLS success rate
	if agg.Summary.TotalSessions > 100 && agg.Summary.OverallTLSRate >= 99 {
		result.addInsight(Insight{
			Severity:    SeverityInfo,
			Category:    CategoryTLS,
			Title:       "Excellent TLS compliance",
			Description: fmt.Sprintf("Overall %.1f%% success rate across %d sessions", agg.Summary.OverallTLSRate, agg.Summary.TotalSessions),
		})
	}

	// No reports received
	if agg.Summary.TotalDMARCReports == 0 && agg.Summary.TotalTLSReports == 0 && agg.Summary.TotalForensicReports == 0 {
		result.addInsight(Insight{
			Severity:    SeverityWarning,
			Category:    CategoryPolicy,
			Title:       "No reports found",
			Description: "No valid DMARC, TLS-RPT, or forensic reports were processed",
			Suggestion:  "Ensure DMARC and TLS-RPT DNS records are configured correctly",
		})
	}

	// Summary of forensic reports if present
	if agg.Summary.TotalForensicReports > 0 {
		result.addInsight(Insight{
			Severity:    SeverityInfo,
			Category:    CategoryForensic,
			Title:       "Forensic reports processed",
			Description: fmt.Sprintf("%d DMARC forensic (failure) reports were processed", agg.Summary.TotalForensicReports),
			Suggestion:  "Review forensic reports for detailed failure information",
		})
	}
}

func (r *InsightsResult) addInsight(insight Insight) {
	r.Insights = append(r.Insights, insight)
}
