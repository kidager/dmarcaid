package analysis

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kidager/dmarcaid/pkg/types"
)

func TestGenerateInsights(t *testing.T) {
	t.Run("detects low DMARC pass rate", func(t *testing.T) {
		result := &types.ParseResult{
			DMARCReports: []types.DMARCReport{
				{Domain: "example.com", TotalMessages: 100, Pass: 80, Fail: 20},
			},
		}

		agg := Aggregate(result)
		insights := GenerateInsights(agg)

		require.NotEmpty(t, insights.Insights)
		found := findInsightByTitle(insights, "Low DMARC pass rate")
		require.NotNil(t, found, "should detect low pass rate")
		assert.Equal(t, SeverityCritical, found.Severity)
		assert.Equal(t, "example.com", found.Domain)
	})

	t.Run("detects warning level pass rate", func(t *testing.T) {
		result := &types.ParseResult{
			DMARCReports: []types.DMARCReport{
				{Domain: "example.com", TotalMessages: 100, Pass: 95, Fail: 5},
			},
		}

		agg := Aggregate(result)
		insights := GenerateInsights(agg)

		found := findInsightByTitle(insights, "DMARC pass rate below optimal")
		require.NotNil(t, found)
		assert.Equal(t, SeverityWarning, found.Severity)
	})

	t.Run("detects messages failing both SPF and DKIM", func(t *testing.T) {
		result := &types.ParseResult{
			DMARCReports: []types.DMARCReport{
				{
					Domain:        "example.com",
					TotalMessages: 100,
					Pass:          90,
					Fail:          10,
					Breakdown:     types.AuthBreakdown{Neither: 5},
				},
			},
		}

		agg := Aggregate(result)
		insights := GenerateInsights(agg)

		found := findInsightByTitle(insights, "Messages failing both SPF and DKIM")
		require.NotNil(t, found)
		assert.Equal(t, SeverityCritical, found.Severity)
	})

	t.Run("detects TLS failures", func(t *testing.T) {
		result := &types.ParseResult{
			TLSReports: []types.TLSReport{
				{
					Domain:        "example.com",
					TotalSessions: 100,
					Success:       80,
					Failure:       20,
					Failures: []types.TLSFailure{
						{Type: "certificate-expired", Count: 20},
					},
				},
			},
		}

		agg := Aggregate(result)
		insights := GenerateInsights(agg)

		found := findInsightByTitle(insights, "Low TLS success rate")
		require.NotNil(t, found)
		assert.Equal(t, SeverityCritical, found.Severity)

		certExpired := findInsightByTitle(insights, "TLS failure: certificate-expired")
		require.NotNil(t, certExpired)
		assert.Equal(t, SeverityCritical, certExpired.Severity)
	})

	t.Run("counts insights by severity", func(t *testing.T) {
		result := &types.ParseResult{
			DMARCReports: []types.DMARCReport{
				{
					Domain:        "example.com",
					TotalMessages: 100,
					Pass:          80,
					Fail:          20,
					Breakdown:     types.AuthBreakdown{Neither: 5},
					PolicyApplied: types.PolicyStats{Reject: 3},
				},
			},
		}

		agg := Aggregate(result)
		insights := GenerateInsights(agg)

		assert.Greater(t, insights.CriticalCount, 0)
		assert.Equal(t, insights.CriticalCount+insights.WarningCount+insights.InfoCount, len(insights.Insights))
	})

	t.Run("no insights for perfect compliance", func(t *testing.T) {
		result := &types.ParseResult{
			DMARCReports: []types.DMARCReport{
				{
					Domain:        "example.com",
					TotalMessages: 100,
					Pass:          100,
					Fail:          0,
					Breakdown:     types.AuthBreakdown{SPFAndDKIM: 100},
					SPF:           types.SPFDetails{Pass: 100, Aligned: 100},
					DKIM:          types.DKIMDetails{Pass: 100, Aligned: 100},
				},
			},
			TLSReports: []types.TLSReport{
				{
					Domain:        "example.com",
					TotalSessions: 100,
					Success:       100,
					Failure:       0,
				},
			},
		}

		agg := Aggregate(result)
		insights := GenerateInsights(agg)

		// Should only have positive insights
		for _, insight := range insights.Insights {
			if insight.Domain == "example.com" {
				assert.NotEqual(t, SeverityCritical, insight.Severity, "should not have critical insights for perfect compliance")
			}
		}
	})

	t.Run("sorts insights by severity", func(t *testing.T) {
		result := &types.ParseResult{
			DMARCReports: []types.DMARCReport{
				{
					Domain:        "example.com",
					TotalMessages: 100,
					Pass:          80,
					Fail:          20,
					Breakdown:     types.AuthBreakdown{Neither: 5},
					PolicyApplied: types.PolicyStats{Quarantine: 3},
				},
			},
		}

		agg := Aggregate(result)
		insights := GenerateInsights(agg)

		// Critical should come before warning, warning before info
		var lastSeverity = SeverityCritical + 1
		for _, insight := range insights.Insights {
			assert.LessOrEqual(t, int(insight.Severity), int(lastSeverity), "insights should be sorted by severity descending")
			if insight.Severity < lastSeverity {
				lastSeverity = insight.Severity
			}
		}
	})
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityInfo, "info"},
		{SeverityWarning, "warning"},
		{SeverityCritical, "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.severity.String())
		})
	}
}

func findInsightByTitle(insights *InsightsResult, title string) *Insight {
	for _, i := range insights.Insights {
		if i.Title == title {
			return &i
		}
	}
	return nil
}
