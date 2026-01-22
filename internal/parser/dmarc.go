// Package parser provides parsers for DMARC and TLS-RPT reports.
package parser

import (
	"encoding/xml"
	"fmt"
	"io"
	"time"

	"github.com/kidager/dmarcaid/pkg/types"
)

// dmarcFeedback represents the root element of a DMARC aggregate report.
type dmarcFeedback struct {
	XMLName         xml.Name             `xml:"feedback"`
	ReportMetadata  dmarcReportMetadata  `xml:"report_metadata"`
	PolicyPublished dmarcPolicyPublished `xml:"policy_published"`
	Records         []dmarcRecord        `xml:"record"`
}

type dmarcReportMetadata struct {
	OrgName   string         `xml:"org_name"`
	Email     string         `xml:"email"`
	ReportID  string         `xml:"report_id"`
	DateRange dmarcDateRange `xml:"date_range"`
}

type dmarcDateRange struct {
	Begin int64 `xml:"begin"`
	End   int64 `xml:"end"`
}

type dmarcPolicyPublished struct {
	Domain string `xml:"domain"`
	ADKIM  string `xml:"adkim"`
	ASPF   string `xml:"aspf"`
	P      string `xml:"p"`
	SP     string `xml:"sp"`
	Pct    int    `xml:"pct"`
}

type dmarcRecord struct {
	Row         dmarcRow         `xml:"row"`
	Identifiers dmarcIdentifiers `xml:"identifiers"`
	AuthResults dmarcAuthResults `xml:"auth_results"`
}

type dmarcRow struct {
	SourceIP        string               `xml:"source_ip"`
	Count           int                  `xml:"count"`
	PolicyEvaluated dmarcPolicyEvaluated `xml:"policy_evaluated"`
}

type dmarcPolicyEvaluated struct {
	Disposition string              `xml:"disposition"`
	DKIM        string              `xml:"dkim"`
	SPF         string              `xml:"spf"`
	Reason      []dmarcPolicyReason `xml:"reason"`
}

type dmarcPolicyReason struct {
	Type    string `xml:"type"`
	Comment string `xml:"comment"`
}

type dmarcIdentifiers struct {
	HeaderFrom   string `xml:"header_from"`
	EnvelopeFrom string `xml:"envelope_from"`
	EnvelopeTo   string `xml:"envelope_to"`
}

type dmarcAuthResults struct {
	DKIM []dmarcDKIMResult `xml:"dkim"`
	SPF  []dmarcSPFResult  `xml:"spf"`
}

type dmarcDKIMResult struct {
	Domain      string `xml:"domain"`
	Selector    string `xml:"selector"`
	Result      string `xml:"result"`
	HumanResult string `xml:"human_result"`
}

type dmarcSPFResult struct {
	Domain string `xml:"domain"`
	Scope  string `xml:"scope"`
	Result string `xml:"result"`
}

// ParseDMARC parses a DMARC aggregate report from an io.Reader.
func ParseDMARC(r io.Reader) (*types.DMARCReport, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading data: %w", err)
	}

	return ParseDMARCBytes(data)
}

// ParseDMARCBytes parses a DMARC aggregate report from bytes.
func ParseDMARCBytes(data []byte) (*types.DMARCReport, error) {
	var feedback dmarcFeedback
	if err := xml.Unmarshal(data, &feedback); err != nil {
		return nil, fmt.Errorf("parsing XML: %w", err)
	}

	return convertDMARCFeedback(&feedback), nil
}

// convertDMARCFeedback converts the XML structure to our domain types.
func convertDMARCFeedback(f *dmarcFeedback) *types.DMARCReport {
	report := &types.DMARCReport{
		Domain: f.PolicyPublished.Domain,
		Period: types.Period{
			Begin: time.Unix(f.ReportMetadata.DateRange.Begin, 0).UTC(),
			End:   time.Unix(f.ReportMetadata.DateRange.End, 0).UTC(),
		},
		Reporters: []string{f.ReportMetadata.OrgName},
	}

	// Track unique selectors
	selectors := make(map[string]struct{})

	for _, record := range f.Records {
		count := record.Row.Count
		report.TotalMessages += count

		// DMARC result (policy evaluation)
		dmarcPass := record.Row.PolicyEvaluated.DKIM == "pass" || record.Row.PolicyEvaluated.SPF == "pass"
		if dmarcPass {
			report.Pass += count
		} else {
			report.Fail += count
		}

		// Authentication breakdown
		dkimPass := record.Row.PolicyEvaluated.DKIM == "pass"
		spfPass := record.Row.PolicyEvaluated.SPF == "pass"

		switch {
		case dkimPass && spfPass:
			report.Breakdown.SPFAndDKIM += count
		case dkimPass && !spfPass:
			report.Breakdown.DKIMOnly += count
		case !dkimPass && spfPass:
			report.Breakdown.SPFOnly += count
		default:
			report.Breakdown.Neither += count
		}

		// SPF details from auth_results
		for _, spf := range record.AuthResults.SPF {
			switch spf.Result {
			case "pass":
				report.SPF.Pass += count
			case "fail":
				report.SPF.Fail += count
			case "softfail":
				report.SPF.SoftFail += count
			case "neutral":
				report.SPF.Neutral += count
			}

			// SPF alignment (envelope_from matches header_from)
			if spf.Domain == record.Identifiers.HeaderFrom {
				report.SPF.Aligned += count
			}
		}

		// DKIM details from auth_results
		for _, dkim := range record.AuthResults.DKIM {
			switch dkim.Result {
			case "pass":
				report.DKIM.Pass += count
			case "fail":
				report.DKIM.Fail += count
			}

			// DKIM alignment (signing domain matches header_from)
			if dkim.Domain == record.Identifiers.HeaderFrom {
				report.DKIM.Aligned += count
			}

			if dkim.Selector != "" {
				selectors[dkim.Selector] = struct{}{}
			}
		}

		// Policy applied
		switch record.Row.PolicyEvaluated.Disposition {
		case "none":
			report.PolicyApplied.None += count
		case "quarantine":
			report.PolicyApplied.Quarantine += count
		case "reject":
			report.PolicyApplied.Reject += count
		}

		// Build source entry
		source := types.Source{
			IP:    record.Row.SourceIP,
			Count: count,
		}
		if len(record.AuthResults.SPF) > 0 {
			source.SPFResult = record.AuthResults.SPF[0].Result
		}
		if len(record.AuthResults.DKIM) > 0 {
			source.DKIMResult = record.AuthResults.DKIM[0].Result
		}
		if dmarcPass {
			source.PassRate = 100.0
		}
		report.Sources = append(report.Sources, source)

		// Track failures
		if !dmarcPass {
			failure := types.Failure{
				HeaderFrom:   record.Identifiers.HeaderFrom,
				EnvelopeFrom: record.Identifiers.EnvelopeFrom,
				SourceIP:     record.Row.SourceIP,
				Count:        count,
				Disposition:  record.Row.PolicyEvaluated.Disposition,
			}
			if len(record.AuthResults.SPF) > 0 {
				failure.SPFResult = record.AuthResults.SPF[0].Result
			}
			if len(record.AuthResults.DKIM) > 0 {
				failure.DKIMResult = record.AuthResults.DKIM[0].Result
				failure.DKIMSelector = record.AuthResults.DKIM[0].Selector
			}
			report.Failures = append(report.Failures, failure)
		}
	}

	// Convert selectors map to slice
	for sel := range selectors {
		report.DKIM.Selectors = append(report.DKIM.Selectors, sel)
	}

	return report
}
