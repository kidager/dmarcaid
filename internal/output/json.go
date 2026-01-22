package output

import (
	"encoding/json"

	"github.com/kidager/dmarcaid/internal/analysis"
	"github.com/kidager/dmarcaid/pkg/types"
)

// JSONOutput represents the JSON output structure.
type JSONOutput struct {
	Summary  JSONSummary          `json:"summary"`
	DMARC    []JSONDMARCReport    `json:"dmarc,omitempty"`
	TLSRPT   []JSONTLSReport      `json:"tlsrpt,omitempty"`
	Forensic []JSONForensicReport `json:"forensic,omitempty"`
	Insights *JSONInsightsResult  `json:"insights,omitempty"`
	Errors   []types.ParseError   `json:"errors,omitempty"`
}

// JSONInsightsResult contains insights for JSON output.
type JSONInsightsResult struct {
	CriticalCount int           `json:"critical_count"`
	WarningCount  int           `json:"warning_count"`
	InfoCount     int           `json:"info_count"`
	Items         []JSONInsight `json:"items,omitempty"`
}

// JSONInsight represents a single insight in JSON format.
type JSONInsight struct {
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Domain      string `json:"domain,omitempty"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Suggestion  string `json:"suggestion,omitempty"`
}

// JSONSummary contains file parsing summary.
type JSONSummary struct {
	FilesParsed   int `json:"files_parsed"`
	DMARCFiles    int `json:"dmarc_files"`
	TLSFiles      int `json:"tls_files"`
	ForensicFiles int `json:"forensic_files"`
	ErrorCount    int `json:"error_count"`
}

// JSONDMARCReport is the JSON representation of a DMARC report.
type JSONDMARCReport struct {
	Domain        string             `json:"domain"`
	Period        JSONPeriod         `json:"period"`
	Reporters     []string           `json:"reporters"`
	TotalMessages int                `json:"total_messages"`
	Pass          int                `json:"pass"`
	Fail          int                `json:"fail"`
	PassRate      float64            `json:"pass_rate"`
	Breakdown     *JSONAuthBreakdown `json:"breakdown,omitempty"`
	SPF           *JSONSPFDetails    `json:"spf,omitempty"`
	DKIM          *JSONDKIMDetails   `json:"dkim,omitempty"`
	Policy        *JSONPolicyStats   `json:"policy,omitempty"`
	Sources       []JSONSource       `json:"sources,omitempty"`
	Failures      []JSONDMARCFailure `json:"failures,omitempty"`
}

// JSONPeriod represents a time range.
type JSONPeriod struct {
	Begin string `json:"begin"`
	End   string `json:"end"`
}

// JSONAuthBreakdown shows authentication combinations.
type JSONAuthBreakdown struct {
	SPFAndDKIM int `json:"spf_and_dkim"`
	DKIMOnly   int `json:"dkim_only"`
	SPFOnly    int `json:"spf_only"`
	Neither    int `json:"neither"`
}

// JSONSPFDetails contains SPF statistics.
type JSONSPFDetails struct {
	Pass     int `json:"pass"`
	Fail     int `json:"fail"`
	SoftFail int `json:"softfail"`
	Neutral  int `json:"neutral"`
	Aligned  int `json:"aligned"`
}

// JSONDKIMDetails contains DKIM statistics.
type JSONDKIMDetails struct {
	Pass      int      `json:"pass"`
	Fail      int      `json:"fail"`
	Aligned   int      `json:"aligned"`
	Selectors []string `json:"selectors,omitempty"`
}

// JSONPolicyStats tracks disposition outcomes.
type JSONPolicyStats struct {
	None       int `json:"none"`
	Quarantine int `json:"quarantine"`
	Reject     int `json:"reject"`
}

// JSONSource represents an email source.
type JSONSource struct {
	IP         string  `json:"ip"`
	PTR        string  `json:"ptr,omitempty"`
	Count      int     `json:"count"`
	PassRate   float64 `json:"pass_rate"`
	SPFResult  string  `json:"spf_result"`
	DKIMResult string  `json:"dkim_result"`
}

// JSONDMARCFailure represents a DMARC failure.
type JSONDMARCFailure struct {
	HeaderFrom   string `json:"header_from"`
	EnvelopeFrom string `json:"envelope_from,omitempty"`
	SourceIP     string `json:"source_ip"`
	PTR          string `json:"ptr,omitempty"`
	SPFResult    string `json:"spf_result"`
	DKIMResult   string `json:"dkim_result"`
	DKIMSelector string `json:"dkim_selector,omitempty"`
	Count        int    `json:"count"`
	Disposition  string `json:"disposition"`
}

// JSONTLSReport is the JSON representation of a TLS-RPT report.
type JSONTLSReport struct {
	Domain        string           `json:"domain"`
	Period        JSONPeriod       `json:"period"`
	Reporters     []string         `json:"reporters"`
	TotalSessions int              `json:"total_sessions"`
	Success       int              `json:"success"`
	Failure       int              `json:"failure"`
	SuccessRate   float64          `json:"success_rate"`
	Failures      []JSONTLSFailure `json:"failures,omitempty"`
}

// JSONTLSFailure represents a TLS failure.
type JSONTLSFailure struct {
	Type         string `json:"type"`
	SendingMTA   string `json:"sending_mta"`
	ReceivingMTA string `json:"receiving_mta"`
	Count        int    `json:"count"`
}

// JSONForensicReport is the JSON representation of a DMARC forensic report.
type JSONForensicReport struct {
	Domain           string            `json:"domain"`
	ReportedDomain   string            `json:"reported_domain,omitempty"`
	Reporters        []string          `json:"reporters"`
	ArrivalDate      string            `json:"arrival_date,omitempty"`
	SourceIP         string            `json:"source_ip"`
	FeedbackType     string            `json:"feedback_type,omitempty"`
	OriginalMailFrom string            `json:"original_mail_from,omitempty"`
	OriginalRcptTo   string            `json:"original_rcpt_to,omitempty"`
	Subject          string            `json:"subject,omitempty"`
	MessageID        string            `json:"message_id,omitempty"`
	DKIMDomain       string            `json:"dkim_domain,omitempty"`
	DKIMSelector     string            `json:"dkim_selector,omitempty"`
	SPFResult        string            `json:"spf_result"`
	DKIMResult       string            `json:"dkim_result"`
	DMARCResult      string            `json:"dmarc_result"`
	DeliveryResult   string            `json:"delivery_result,omitempty"`
	OriginalHeaders  map[string]string `json:"original_headers,omitempty"`
}

// ToJSON converts parse results to JSON string.
func ToJSON(result *types.ParseResult, detailed bool) (string, error) {
	output := JSONOutput{
		Summary: JSONSummary{
			FilesParsed:   result.FilesParsed,
			DMARCFiles:    result.DMARCFiles,
			TLSFiles:      result.TLSFiles,
			ForensicFiles: result.ForensicFiles,
			ErrorCount:    len(result.Errors),
		},
		Errors: result.Errors,
	}

	// Convert DMARC reports
	for _, r := range result.DMARCReports {
		jr := JSONDMARCReport{
			Domain:        r.Domain,
			Period:        JSONPeriod{Begin: r.Period.Begin.Format("2006-01-02"), End: r.Period.End.Format("2006-01-02")},
			Reporters:     r.Reporters,
			TotalMessages: r.TotalMessages,
			Pass:          r.Pass,
			Fail:          r.Fail,
			PassRate:      calculateRate(r.Pass, r.TotalMessages),
		}

		if detailed {
			jr.Breakdown = &JSONAuthBreakdown{
				SPFAndDKIM: r.Breakdown.SPFAndDKIM,
				DKIMOnly:   r.Breakdown.DKIMOnly,
				SPFOnly:    r.Breakdown.SPFOnly,
				Neither:    r.Breakdown.Neither,
			}
			jr.SPF = &JSONSPFDetails{
				Pass:     r.SPF.Pass,
				Fail:     r.SPF.Fail,
				SoftFail: r.SPF.SoftFail,
				Neutral:  r.SPF.Neutral,
				Aligned:  r.SPF.Aligned,
			}
			jr.DKIM = &JSONDKIMDetails{
				Pass:      r.DKIM.Pass,
				Fail:      r.DKIM.Fail,
				Aligned:   r.DKIM.Aligned,
				Selectors: r.DKIM.Selectors,
			}
			jr.Policy = &JSONPolicyStats{
				None:       r.PolicyApplied.None,
				Quarantine: r.PolicyApplied.Quarantine,
				Reject:     r.PolicyApplied.Reject,
			}

			for _, src := range r.Sources {
				jr.Sources = append(jr.Sources, JSONSource{
					IP:         src.IP,
					PTR:        src.PTR,
					Count:      src.Count,
					PassRate:   src.PassRate,
					SPFResult:  src.SPFResult,
					DKIMResult: src.DKIMResult,
				})
			}

			for _, f := range r.Failures {
				jr.Failures = append(jr.Failures, JSONDMARCFailure{
					HeaderFrom:   f.HeaderFrom,
					EnvelopeFrom: f.EnvelopeFrom,
					SourceIP:     f.SourceIP,
					PTR:          f.PTR,
					SPFResult:    f.SPFResult,
					DKIMResult:   f.DKIMResult,
					DKIMSelector: f.DKIMSelector,
					Count:        f.Count,
					Disposition:  f.Disposition,
				})
			}
		}

		output.DMARC = append(output.DMARC, jr)
	}

	// Convert TLS reports
	for _, r := range result.TLSReports {
		jr := JSONTLSReport{
			Domain:        r.Domain,
			Period:        JSONPeriod{Begin: r.Period.Begin.Format("2006-01-02"), End: r.Period.End.Format("2006-01-02")},
			Reporters:     r.Reporters,
			TotalSessions: r.TotalSessions,
			Success:       r.Success,
			Failure:       r.Failure,
			SuccessRate:   calculateRate(r.Success, r.TotalSessions),
		}

		if detailed {
			for _, f := range r.Failures {
				jr.Failures = append(jr.Failures, JSONTLSFailure{
					Type:         f.Type,
					SendingMTA:   f.SendingMTA,
					ReceivingMTA: f.ReceivingMTA,
					Count:        f.Count,
				})
			}
		}

		output.TLSRPT = append(output.TLSRPT, jr)
	}

	// Convert forensic reports
	for _, r := range result.ForensicReports {
		jr := convertForensicReport(r, detailed)
		output.Forensic = append(output.Forensic, jr)
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func calculateRate(success, total int) float64 {
	if total == 0 {
		return 100.0
	}
	return float64(success) / float64(total) * 100
}

// ToJSONWithInsights converts parse results and insights to JSON string.
func ToJSONWithInsights(result *types.ParseResult, insights *analysis.InsightsResult, detailed bool) (string, error) {
	output := JSONOutput{
		Summary: JSONSummary{
			FilesParsed:   result.FilesParsed,
			DMARCFiles:    result.DMARCFiles,
			TLSFiles:      result.TLSFiles,
			ForensicFiles: result.ForensicFiles,
			ErrorCount:    len(result.Errors),
		},
		Errors: result.Errors,
	}

	// Convert DMARC reports
	for _, r := range result.DMARCReports {
		jr := convertDMARCReport(r, detailed)
		output.DMARC = append(output.DMARC, jr)
	}

	// Convert TLS reports
	for _, r := range result.TLSReports {
		jr := convertTLSReport(r, detailed)
		output.TLSRPT = append(output.TLSRPT, jr)
	}

	// Convert forensic reports
	for _, r := range result.ForensicReports {
		jr := convertForensicReport(r, detailed)
		output.Forensic = append(output.Forensic, jr)
	}

	// Convert insights
	if insights != nil && len(insights.Insights) > 0 {
		output.Insights = &JSONInsightsResult{
			CriticalCount: insights.CriticalCount,
			WarningCount:  insights.WarningCount,
			InfoCount:     insights.InfoCount,
		}
		for _, i := range insights.Insights {
			output.Insights.Items = append(output.Insights.Items, JSONInsight{
				Severity:    i.Severity.String(),
				Category:    string(i.Category),
				Domain:      i.Domain,
				Title:       i.Title,
				Description: i.Description,
				Suggestion:  i.Suggestion,
			})
		}
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func convertDMARCReport(r types.DMARCReport, detailed bool) JSONDMARCReport {
	jr := JSONDMARCReport{
		Domain:        r.Domain,
		Period:        JSONPeriod{Begin: r.Period.Begin.Format("2006-01-02"), End: r.Period.End.Format("2006-01-02")},
		Reporters:     r.Reporters,
		TotalMessages: r.TotalMessages,
		Pass:          r.Pass,
		Fail:          r.Fail,
		PassRate:      calculateRate(r.Pass, r.TotalMessages),
	}

	if detailed {
		jr.Breakdown = &JSONAuthBreakdown{
			SPFAndDKIM: r.Breakdown.SPFAndDKIM,
			DKIMOnly:   r.Breakdown.DKIMOnly,
			SPFOnly:    r.Breakdown.SPFOnly,
			Neither:    r.Breakdown.Neither,
		}
		jr.SPF = &JSONSPFDetails{
			Pass:     r.SPF.Pass,
			Fail:     r.SPF.Fail,
			SoftFail: r.SPF.SoftFail,
			Neutral:  r.SPF.Neutral,
			Aligned:  r.SPF.Aligned,
		}
		jr.DKIM = &JSONDKIMDetails{
			Pass:      r.DKIM.Pass,
			Fail:      r.DKIM.Fail,
			Aligned:   r.DKIM.Aligned,
			Selectors: r.DKIM.Selectors,
		}
		jr.Policy = &JSONPolicyStats{
			None:       r.PolicyApplied.None,
			Quarantine: r.PolicyApplied.Quarantine,
			Reject:     r.PolicyApplied.Reject,
		}

		for _, src := range r.Sources {
			jr.Sources = append(jr.Sources, JSONSource{
				IP:         src.IP,
				PTR:        src.PTR,
				Count:      src.Count,
				PassRate:   src.PassRate,
				SPFResult:  src.SPFResult,
				DKIMResult: src.DKIMResult,
			})
		}

		for _, f := range r.Failures {
			jr.Failures = append(jr.Failures, JSONDMARCFailure{
				HeaderFrom:   f.HeaderFrom,
				EnvelopeFrom: f.EnvelopeFrom,
				SourceIP:     f.SourceIP,
				PTR:          f.PTR,
				SPFResult:    f.SPFResult,
				DKIMResult:   f.DKIMResult,
				DKIMSelector: f.DKIMSelector,
				Count:        f.Count,
				Disposition:  f.Disposition,
			})
		}
	}

	return jr
}

func convertTLSReport(r types.TLSReport, detailed bool) JSONTLSReport {
	jr := JSONTLSReport{
		Domain:        r.Domain,
		Period:        JSONPeriod{Begin: r.Period.Begin.Format("2006-01-02"), End: r.Period.End.Format("2006-01-02")},
		Reporters:     r.Reporters,
		TotalSessions: r.TotalSessions,
		Success:       r.Success,
		Failure:       r.Failure,
		SuccessRate:   calculateRate(r.Success, r.TotalSessions),
	}

	if detailed {
		for _, f := range r.Failures {
			jr.Failures = append(jr.Failures, JSONTLSFailure{
				Type:         f.Type,
				SendingMTA:   f.SendingMTA,
				ReceivingMTA: f.ReceivingMTA,
				Count:        f.Count,
			})
		}
	}

	return jr
}

func convertForensicReport(r types.ForensicReport, detailed bool) JSONForensicReport {
	jr := JSONForensicReport{
		Domain:         r.Domain,
		ReportedDomain: r.ReportedDomain,
		Reporters:      r.Reporters,
		SourceIP:       r.SourceIP,
		FeedbackType:   r.FeedbackType,
		SPFResult:      r.SPFResult,
		DKIMResult:     r.DKIMResult,
		DMARCResult:    r.DMARCResult,
		DeliveryResult: r.DeliveryResult,
	}

	if !r.ArrivalDate.IsZero() {
		jr.ArrivalDate = r.ArrivalDate.Format("2006-01-02T15:04:05Z07:00")
	}

	if detailed {
		jr.OriginalMailFrom = r.OriginalMailFrom
		jr.OriginalRcptTo = r.OriginalRcptTo
		jr.Subject = r.Subject
		jr.MessageID = r.MessageID
		jr.DKIMDomain = r.DKIMDomain
		jr.DKIMSelector = r.DKIMSelector
		jr.OriginalHeaders = r.OriginalHeaders
	}

	return jr
}
