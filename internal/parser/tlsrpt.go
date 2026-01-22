package parser

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/kidager/dmarcaid/pkg/types"
)

// tlsReport represents the JSON structure of a TLS-RPT report.
type tlsReport struct {
	OrganizationName string       `json:"organization-name"`
	DateRange        tlsDateRange `json:"date-range"`
	ContactInfo      string       `json:"contact-info"`
	ReportID         string       `json:"report-id"`
	Policies         []tlsPolicy  `json:"policies"`
}

type tlsDateRange struct {
	StartDatetime string `json:"start-datetime"`
	EndDatetime   string `json:"end-datetime"`
}

type tlsPolicy struct {
	Policy         tlsPolicyDetails   `json:"policy"`
	Summary        tlsSummary         `json:"summary"`
	FailureDetails []tlsFailureDetail `json:"failure-details"`
}

type tlsPolicyDetails struct {
	PolicyType   string   `json:"policy-type"`
	PolicyString []string `json:"policy-string"`
	PolicyDomain string   `json:"policy-domain"`
	MXHost       []string `json:"mx-host"`
}

type tlsSummary struct {
	TotalSuccessfulSessionCount int `json:"total-successful-session-count"`
	TotalFailureSessionCount    int `json:"total-failure-session-count"`
}

type tlsFailureDetail struct {
	ResultType          string `json:"result-type"`
	SendingMTAIP        string `json:"sending-mta-ip"`
	ReceivingMXHostname string `json:"receiving-mx-hostname"`
	ReceivingIP         string `json:"receiving-ip"`
	FailedSessionCount  int    `json:"failed-session-count"`
	AdditionalInfo      string `json:"additional-information"`
	FailureReasonCode   string `json:"failure-reason-code"`
}

// ParseTLSRPT parses a TLS-RPT report from an io.Reader.
func ParseTLSRPT(r io.Reader) (*types.TLSReport, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading data: %w", err)
	}

	return ParseTLSRPTBytes(data)
}

// ParseTLSRPTBytes parses a TLS-RPT report from bytes.
func ParseTLSRPTBytes(data []byte) (*types.TLSReport, error) {
	var raw tlsReport
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	return convertTLSReport(&raw), nil
}

// convertTLSReport converts the JSON structure to our domain types.
func convertTLSReport(r *tlsReport) *types.TLSReport {
	report := &types.TLSReport{
		Reporters: []string{r.OrganizationName},
	}

	// Parse date range
	if start, err := time.Parse(time.RFC3339, r.DateRange.StartDatetime); err == nil {
		report.Period.Begin = start.UTC()
	}
	if end, err := time.Parse(time.RFC3339, r.DateRange.EndDatetime); err == nil {
		report.Period.End = end.UTC()
	}

	// Process policies
	for _, policy := range r.Policies {
		// Set domain from policy
		if report.Domain == "" {
			report.Domain = policy.Policy.PolicyDomain
		}

		report.TotalSessions += policy.Summary.TotalSuccessfulSessionCount + policy.Summary.TotalFailureSessionCount
		report.Success += policy.Summary.TotalSuccessfulSessionCount
		report.Failure += policy.Summary.TotalFailureSessionCount

		// Process failure details
		for _, fd := range policy.FailureDetails {
			failure := types.TLSFailure{
				Type:         fd.ResultType,
				SendingMTA:   fd.SendingMTAIP,
				ReceivingMTA: fd.ReceivingMXHostname,
				Count:        fd.FailedSessionCount,
			}
			report.Failures = append(report.Failures, failure)
		}
	}

	return report
}
