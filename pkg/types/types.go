// Package types contains shared data types for dmarcaid.
package types

import "time"

// Period represents a time range for a report.
type Period struct {
	Begin time.Time
	End   time.Time
}

// DMARCReport represents an aggregated DMARC report for a domain.
type DMARCReport struct {
	Domain        string
	Period        Period
	Reporters     []string
	TotalMessages int
	Pass          int
	Fail          int

	Breakdown     AuthBreakdown
	SPF           SPFDetails
	DKIM          DKIMDetails
	PolicyApplied PolicyStats
	Sources       []Source
	Failures      []Failure
}

// AuthBreakdown shows authentication method combinations.
type AuthBreakdown struct {
	SPFAndDKIM int // Both passed
	DKIMOnly   int // DKIM pass, SPF fail
	SPFOnly    int // SPF pass, DKIM fail
	Neither    int // Both failed
}

// SPFDetails contains SPF-specific statistics.
type SPFDetails struct {
	Pass     int
	Fail     int
	SoftFail int
	Neutral  int
	Aligned  int
}

// DKIMDetails contains DKIM-specific statistics.
type DKIMDetails struct {
	Pass      int
	Fail      int
	Aligned   int
	Selectors []string
}

// PolicyStats tracks disposition outcomes.
type PolicyStats struct {
	None       int
	Quarantine int
	Reject     int
}

// Source represents an email source in DMARC reports.
type Source struct {
	IP         string
	PTR        string
	Count      int
	PassRate   float64
	SPFResult  string
	DKIMResult string
}

// Failure represents a DMARC failure record.
type Failure struct {
	HeaderFrom   string
	EnvelopeFrom string
	SourceIP     string
	PTR          string
	SPFResult    string
	DKIMResult   string
	DKIMSelector string
	Count        int
	Disposition  string
}

// TLSReport represents an aggregated TLS-RPT report for a domain.
type TLSReport struct {
	Domain        string
	Period        Period
	Reporters     []string
	TotalSessions int
	Success       int
	Failure       int
	Failures      []TLSFailure
}

// TLSFailure represents a TLS failure record.
type TLSFailure struct {
	Type         string
	SendingMTA   string
	ReceivingMTA string
	Count        int
}

// ForensicReport represents a DMARC forensic/failure report (RUF).
type ForensicReport struct {
	Domain           string
	ReportedDomain   string
	Reporters        []string
	ArrivalDate      time.Time
	SourceIP         string
	FeedbackType     string
	UserAgent        string
	AuthResults      string
	OriginalMailFrom string
	OriginalRcptTo   string
	Subject          string
	MessageID        string

	// DKIM details
	DKIMDomain   string
	DKIMIdentity string
	DKIMSelector string

	// Authentication results
	SPFResult   string
	DKIMResult  string
	DMARCResult string

	// Delivery result
	DeliveryResult string

	// Original headers (if available)
	OriginalHeaders map[string]string
}

// ParseResult contains the results of parsing report files.
type ParseResult struct {
	DMARCReports    []DMARCReport
	TLSReports      []TLSReport
	ForensicReports []ForensicReport
	FilesParsed     int
	DMARCFiles      int
	TLSFiles        int
	ForensicFiles   int
	Errors          []ParseError
}

// ParseError represents an error encountered while parsing a file.
type ParseError struct {
	File  string
	Error string
}
