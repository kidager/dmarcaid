// Package analysis provides aggregation and analysis of report data.
package analysis

import (
	"sort"
	"strings"
	"time"

	"github.com/kidager/dmarcaid/pkg/types"
)

// AggregatedResult contains aggregated report data by domain.
type AggregatedResult struct {
	DMARC    map[string]*AggregatedDMARC
	TLSRPT   map[string]*AggregatedTLS
	Forensic map[string]*AggregatedForensic
	Summary  AggregationSummary
}

// AggregationSummary provides overall statistics.
type AggregationSummary struct {
	TotalDomains         int
	TotalDMARCReports    int
	TotalTLSReports      int
	TotalForensicReports int
	TotalMessages        int
	TotalSessions        int
	OverallPassRate      float64
	OverallTLSRate       float64
	PeriodStart          time.Time
	PeriodEnd            time.Time
}

// AggregatedDMARC contains aggregated DMARC data for a domain.
type AggregatedDMARC struct {
	Domain        string
	ReportCount   int
	Reporters     map[string]int
	PeriodStart   time.Time
	PeriodEnd     time.Time
	TotalMessages int
	Pass          int
	Fail          int
	PassRate      float64

	Breakdown     types.AuthBreakdown
	SPF           types.SPFDetails
	DKIM          types.DKIMDetails
	PolicyApplied types.PolicyStats

	Sources     map[string]*AggregatedSource
	SourcesList []types.Source
	Failures    []types.Failure
}

// AggregatedSource contains aggregated source data.
type AggregatedSource struct {
	IP          string
	PTR         string
	TotalCount  int
	PassCount   int
	FailCount   int
	SPFResults  map[string]int
	DKIMResults map[string]int
}

// AggregatedTLS contains aggregated TLS-RPT data for a domain.
type AggregatedTLS struct {
	Domain        string
	ReportCount   int
	Reporters     map[string]int
	PeriodStart   time.Time
	PeriodEnd     time.Time
	TotalSessions int
	Success       int
	Failure       int
	SuccessRate   float64

	FailureTypes map[string]int
	Failures     []types.TLSFailure
}

// AggregatedForensic contains aggregated forensic report data for a domain.
type AggregatedForensic struct {
	Domain      string
	ReportCount int
	Reporters   map[string]int
	PeriodStart time.Time
	PeriodEnd   time.Time

	// Authentication result counters
	SPFPass   int
	SPFFail   int
	DKIMPass  int
	DKIMFail  int
	DMARCPass int
	DMARCFail int

	// Source IPs that sent failing messages
	SourceIPs map[string]int

	// Individual forensic reports
	Reports []types.ForensicReport
}

// Aggregate combines multiple reports into aggregated results by domain.
func Aggregate(result *types.ParseResult) *AggregatedResult {
	agg := &AggregatedResult{
		DMARC:    make(map[string]*AggregatedDMARC),
		TLSRPT:   make(map[string]*AggregatedTLS),
		Forensic: make(map[string]*AggregatedForensic),
	}

	// Aggregate DMARC reports
	for _, r := range result.DMARCReports {
		aggregateDMARC(agg, r)
	}

	// Aggregate TLS reports
	for _, r := range result.TLSReports {
		aggregateTLS(agg, r)
	}

	// Aggregate forensic reports
	for _, r := range result.ForensicReports {
		aggregateForensic(agg, r)
	}

	// Calculate summary and rates
	calculateSummary(agg)

	return agg
}

func aggregateDMARC(agg *AggregatedResult, r types.DMARCReport) {
	domain := r.Domain
	if _, exists := agg.DMARC[domain]; !exists {
		agg.DMARC[domain] = &AggregatedDMARC{
			Domain:    domain,
			Reporters: make(map[string]int),
			Sources:   make(map[string]*AggregatedSource),
		}
	}

	d := agg.DMARC[domain]
	d.ReportCount++

	// Track reporters
	for _, rep := range r.Reporters {
		d.Reporters[rep]++
	}

	// Update period
	if d.PeriodStart.IsZero() || r.Period.Begin.Before(d.PeriodStart) {
		d.PeriodStart = r.Period.Begin
	}
	if d.PeriodEnd.IsZero() || r.Period.End.After(d.PeriodEnd) {
		d.PeriodEnd = r.Period.End
	}

	// Aggregate counts
	d.TotalMessages += r.TotalMessages
	d.Pass += r.Pass
	d.Fail += r.Fail

	// Aggregate breakdown
	d.Breakdown.SPFAndDKIM += r.Breakdown.SPFAndDKIM
	d.Breakdown.DKIMOnly += r.Breakdown.DKIMOnly
	d.Breakdown.SPFOnly += r.Breakdown.SPFOnly
	d.Breakdown.Neither += r.Breakdown.Neither

	// Aggregate SPF details
	d.SPF.Pass += r.SPF.Pass
	d.SPF.Fail += r.SPF.Fail
	d.SPF.SoftFail += r.SPF.SoftFail
	d.SPF.Neutral += r.SPF.Neutral
	d.SPF.Aligned += r.SPF.Aligned

	// Aggregate DKIM details
	d.DKIM.Pass += r.DKIM.Pass
	d.DKIM.Fail += r.DKIM.Fail
	d.DKIM.Aligned += r.DKIM.Aligned
	for _, sel := range r.DKIM.Selectors {
		if !contains(d.DKIM.Selectors, sel) {
			d.DKIM.Selectors = append(d.DKIM.Selectors, sel)
		}
	}

	// Aggregate policy stats
	d.PolicyApplied.None += r.PolicyApplied.None
	d.PolicyApplied.Quarantine += r.PolicyApplied.Quarantine
	d.PolicyApplied.Reject += r.PolicyApplied.Reject

	// Aggregate sources
	for _, src := range r.Sources {
		aggregateSource(d, src)
	}

	// Collect failures
	d.Failures = append(d.Failures, r.Failures...)
}

func aggregateSource(d *AggregatedDMARC, src types.Source) {
	if _, exists := d.Sources[src.IP]; !exists {
		d.Sources[src.IP] = &AggregatedSource{
			IP:          src.IP,
			PTR:         src.PTR,
			SPFResults:  make(map[string]int),
			DKIMResults: make(map[string]int),
		}
	}

	s := d.Sources[src.IP]
	s.TotalCount += src.Count
	if src.SPFResult == "pass" && src.DKIMResult == "pass" {
		s.PassCount += src.Count
	} else {
		s.FailCount += src.Count
	}
	s.SPFResults[src.SPFResult] += src.Count
	s.DKIMResults[src.DKIMResult] += src.Count

	// Update PTR if we have one
	if s.PTR == "" && src.PTR != "" {
		s.PTR = src.PTR
	}
}

func aggregateTLS(agg *AggregatedResult, r types.TLSReport) {
	domain := r.Domain
	if _, exists := agg.TLSRPT[domain]; !exists {
		agg.TLSRPT[domain] = &AggregatedTLS{
			Domain:       domain,
			Reporters:    make(map[string]int),
			FailureTypes: make(map[string]int),
		}
	}

	t := agg.TLSRPT[domain]
	t.ReportCount++

	// Track reporters
	for _, rep := range r.Reporters {
		t.Reporters[rep]++
	}

	// Update period
	if t.PeriodStart.IsZero() || r.Period.Begin.Before(t.PeriodStart) {
		t.PeriodStart = r.Period.Begin
	}
	if t.PeriodEnd.IsZero() || r.Period.End.After(t.PeriodEnd) {
		t.PeriodEnd = r.Period.End
	}

	// Aggregate counts
	t.TotalSessions += r.TotalSessions
	t.Success += r.Success
	t.Failure += r.Failure

	// Track failure types
	for _, f := range r.Failures {
		t.FailureTypes[f.Type] += f.Count
		t.Failures = append(t.Failures, f)
	}
}

func aggregateForensic(agg *AggregatedResult, r types.ForensicReport) {
	domain := r.Domain
	if domain == "" {
		domain = r.ReportedDomain
	}
	if domain == "" {
		return // Skip reports without domain
	}

	if _, exists := agg.Forensic[domain]; !exists {
		agg.Forensic[domain] = &AggregatedForensic{
			Domain:    domain,
			Reporters: make(map[string]int),
			SourceIPs: make(map[string]int),
		}
	}

	f := agg.Forensic[domain]
	f.ReportCount++

	// Track reporters
	for _, rep := range r.Reporters {
		f.Reporters[rep]++
	}

	// Update period
	if !r.ArrivalDate.IsZero() {
		if f.PeriodStart.IsZero() || r.ArrivalDate.Before(f.PeriodStart) {
			f.PeriodStart = r.ArrivalDate
		}
		if f.PeriodEnd.IsZero() || r.ArrivalDate.After(f.PeriodEnd) {
			f.PeriodEnd = r.ArrivalDate
		}
	}

	// Count authentication results
	switch strings.ToLower(r.SPFResult) {
	case "pass":
		f.SPFPass++
	case "fail", "failed", "softfail", "neutral", "none":
		f.SPFFail++
	}

	switch strings.ToLower(r.DKIMResult) {
	case "pass":
		f.DKIMPass++
	case "fail", "failed", "none":
		f.DKIMFail++
	}

	switch strings.ToLower(r.DMARCResult) {
	case "pass":
		f.DMARCPass++
	case "fail", "failed":
		f.DMARCFail++
	}

	// Track source IPs
	if r.SourceIP != "" {
		f.SourceIPs[r.SourceIP]++
	}

	// Store the report
	f.Reports = append(f.Reports, r)
}

func calculateSummary(agg *AggregatedResult) {
	// Count unique domains
	domains := make(map[string]bool)
	for d := range agg.DMARC {
		domains[d] = true
	}
	for d := range agg.TLSRPT {
		domains[d] = true
	}
	for d := range agg.Forensic {
		domains[d] = true
	}
	agg.Summary.TotalDomains = len(domains)

	// Forensic stats
	for _, f := range agg.Forensic {
		agg.Summary.TotalForensicReports += f.ReportCount
	}

	// DMARC stats
	var totalPass, totalFail int
	for _, d := range agg.DMARC {
		agg.Summary.TotalDMARCReports += d.ReportCount
		agg.Summary.TotalMessages += d.TotalMessages
		totalPass += d.Pass
		totalFail += d.Fail

		// Calculate domain pass rate
		if d.TotalMessages > 0 {
			d.PassRate = float64(d.Pass) / float64(d.TotalMessages) * 100
		} else {
			d.PassRate = 100
		}

		// Convert sources map to sorted list
		d.SourcesList = nil
		for _, src := range d.Sources {
			passRate := 0.0
			if src.TotalCount > 0 {
				passRate = float64(src.PassCount) / float64(src.TotalCount) * 100
			}

			// Determine primary results
			spfResult := getPrimaryResult(src.SPFResults)
			dkimResult := getPrimaryResult(src.DKIMResults)

			d.SourcesList = append(d.SourcesList, types.Source{
				IP:         src.IP,
				PTR:        src.PTR,
				Count:      src.TotalCount,
				PassRate:   passRate,
				SPFResult:  spfResult,
				DKIMResult: dkimResult,
			})
		}
		// Sort by count descending
		sort.Slice(d.SourcesList, func(i, j int) bool {
			return d.SourcesList[i].Count > d.SourcesList[j].Count
		})

		// Update period bounds
		if agg.Summary.PeriodStart.IsZero() || d.PeriodStart.Before(agg.Summary.PeriodStart) {
			agg.Summary.PeriodStart = d.PeriodStart
		}
		if agg.Summary.PeriodEnd.IsZero() || d.PeriodEnd.After(agg.Summary.PeriodEnd) {
			agg.Summary.PeriodEnd = d.PeriodEnd
		}
	}

	if agg.Summary.TotalMessages > 0 {
		agg.Summary.OverallPassRate = float64(totalPass) / float64(agg.Summary.TotalMessages) * 100
	} else {
		agg.Summary.OverallPassRate = 100
	}

	// TLS stats
	var totalSuccess, totalFailure int
	for _, t := range agg.TLSRPT {
		agg.Summary.TotalTLSReports += t.ReportCount
		agg.Summary.TotalSessions += t.TotalSessions
		totalSuccess += t.Success
		totalFailure += t.Failure

		// Calculate domain success rate
		if t.TotalSessions > 0 {
			t.SuccessRate = float64(t.Success) / float64(t.TotalSessions) * 100
		} else {
			t.SuccessRate = 100
		}

		// Update period bounds
		if agg.Summary.PeriodStart.IsZero() || t.PeriodStart.Before(agg.Summary.PeriodStart) {
			agg.Summary.PeriodStart = t.PeriodStart
		}
		if agg.Summary.PeriodEnd.IsZero() || t.PeriodEnd.After(agg.Summary.PeriodEnd) {
			agg.Summary.PeriodEnd = t.PeriodEnd
		}
	}

	if agg.Summary.TotalSessions > 0 {
		agg.Summary.OverallTLSRate = float64(totalSuccess) / float64(agg.Summary.TotalSessions) * 100
	} else {
		agg.Summary.OverallTLSRate = 100
	}
}

func getPrimaryResult(results map[string]int) string {
	if len(results) == 0 {
		return ""
	}

	var maxResult string
	var maxCount int
	for result, count := range results {
		if count > maxCount {
			maxCount = count
			maxResult = result
		}
	}
	return maxResult
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ToParseResult converts aggregated results back to ParseResult format.
func (agg *AggregatedResult) ToParseResult() *types.ParseResult {
	result := &types.ParseResult{
		FilesParsed:   agg.Summary.TotalDMARCReports + agg.Summary.TotalTLSReports + agg.Summary.TotalForensicReports,
		DMARCFiles:    agg.Summary.TotalDMARCReports,
		TLSFiles:      agg.Summary.TotalTLSReports,
		ForensicFiles: agg.Summary.TotalForensicReports,
	}

	// Convert aggregated DMARC to reports
	for _, d := range agg.DMARC {
		reporters := make([]string, 0, len(d.Reporters))
		for rep := range d.Reporters {
			reporters = append(reporters, rep)
		}
		sort.Strings(reporters)

		report := types.DMARCReport{
			Domain:        d.Domain,
			Period:        types.Period{Begin: d.PeriodStart, End: d.PeriodEnd},
			Reporters:     reporters,
			TotalMessages: d.TotalMessages,
			Pass:          d.Pass,
			Fail:          d.Fail,
			Breakdown:     d.Breakdown,
			SPF:           d.SPF,
			DKIM:          d.DKIM,
			PolicyApplied: d.PolicyApplied,
			Sources:       d.SourcesList,
			Failures:      d.Failures,
		}
		result.DMARCReports = append(result.DMARCReports, report)
	}

	// Sort by domain
	sort.Slice(result.DMARCReports, func(i, j int) bool {
		return result.DMARCReports[i].Domain < result.DMARCReports[j].Domain
	})

	// Convert aggregated TLS to reports
	for _, t := range agg.TLSRPT {
		reporters := make([]string, 0, len(t.Reporters))
		for rep := range t.Reporters {
			reporters = append(reporters, rep)
		}
		sort.Strings(reporters)

		report := types.TLSReport{
			Domain:        t.Domain,
			Period:        types.Period{Begin: t.PeriodStart, End: t.PeriodEnd},
			Reporters:     reporters,
			TotalSessions: t.TotalSessions,
			Success:       t.Success,
			Failure:       t.Failure,
			Failures:      t.Failures,
		}
		result.TLSReports = append(result.TLSReports, report)
	}

	// Sort by domain
	sort.Slice(result.TLSReports, func(i, j int) bool {
		return result.TLSReports[i].Domain < result.TLSReports[j].Domain
	})

	// Convert aggregated forensic to reports
	for _, f := range agg.Forensic {
		// Add all individual forensic reports for this domain
		result.ForensicReports = append(result.ForensicReports, f.Reports...)
	}

	// Sort forensic reports by domain, then by arrival date
	sort.Slice(result.ForensicReports, func(i, j int) bool {
		if result.ForensicReports[i].Domain != result.ForensicReports[j].Domain {
			return result.ForensicReports[i].Domain < result.ForensicReports[j].Domain
		}
		return result.ForensicReports[i].ArrivalDate.Before(result.ForensicReports[j].ArrivalDate)
	})

	return result
}
