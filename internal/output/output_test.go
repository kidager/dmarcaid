package output

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kidager/dmarcaid/internal/analysis"
	"github.com/kidager/dmarcaid/pkg/types"
)

func TestTableOutput(t *testing.T) {
	t.Run("renders DMARC reports", func(t *testing.T) {
		result := &types.ParseResult{
			FilesParsed: 2,
			DMARCFiles:  2,
			DMARCReports: []types.DMARCReport{
				{
					Domain:        "example.com",
					Reporters:     []string{"google.com"},
					TotalMessages: 100,
					Pass:          95,
					Fail:          5,
				},
			},
		}

		output := TableOutput(result, false)

		assert.Contains(t, output, "example.com")
		assert.Contains(t, output, "100")
		assert.Contains(t, output, "95")
		assert.Contains(t, output, "DMARC Reports")
	})

	t.Run("renders TLS reports", func(t *testing.T) {
		result := &types.ParseResult{
			FilesParsed: 1,
			TLSFiles:    1,
			TLSReports: []types.TLSReport{
				{
					Domain:        "example.com",
					Reporters:     []string{"google.com"},
					TotalSessions: 50,
					Success:       48,
					Failure:       2,
				},
			},
		}

		output := TableOutput(result, false)

		assert.Contains(t, output, "example.com")
		assert.Contains(t, output, "50")
		assert.Contains(t, output, "TLS-RPT Reports")
	})

	t.Run("shows errors when present", func(t *testing.T) {
		result := &types.ParseResult{
			Errors: []types.ParseError{
				{File: "bad.xml", Error: "invalid format"},
			},
		}

		output := TableOutput(result, false)

		assert.Contains(t, output, "Errors")
		assert.Contains(t, output, "bad.xml")
		assert.Contains(t, output, "invalid format")
	})

	t.Run("shows details when detailed flag is true", func(t *testing.T) {
		result := &types.ParseResult{
			DMARCReports: []types.DMARCReport{
				{
					Domain:        "example.com",
					TotalMessages: 10,
					Pass:          10,
					Breakdown:     types.AuthBreakdown{SPFAndDKIM: 8, DKIMOnly: 2},
					PolicyApplied: types.PolicyStats{None: 10},
					Sources: []types.Source{
						{IP: "1.2.3.4", Count: 10, SPFResult: "pass", DKIMResult: "pass"},
					},
				},
			},
		}

		output := TableOutput(result, true)

		assert.Contains(t, output, "Auth:")
		assert.Contains(t, output, "SPF+DKIM=8")
		assert.Contains(t, output, "Policy:")
		assert.Contains(t, output, "Sources:")
		assert.Contains(t, output, "1.2.3.4")
	})
}

func TestToJSON(t *testing.T) {
	t.Run("produces valid JSON", func(t *testing.T) {
		result := &types.ParseResult{
			FilesParsed: 1,
			DMARCFiles:  1,
			DMARCReports: []types.DMARCReport{
				{
					Domain:        "example.com",
					Reporters:     []string{"google.com"},
					TotalMessages: 10,
					Pass:          10,
					Period: types.Period{
						Begin: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
						End:   time.Date(2026, 1, 1, 23, 59, 59, 0, time.UTC),
					},
				},
			},
		}

		jsonStr, err := ToJSON(result, false)
		require.NoError(t, err)

		var parsed JSONOutput
		err = json.Unmarshal([]byte(jsonStr), &parsed)
		require.NoError(t, err)

		assert.Equal(t, 1, parsed.Summary.FilesParsed)
		require.Len(t, parsed.DMARC, 1)
		assert.Equal(t, "example.com", parsed.DMARC[0].Domain)
		assert.Equal(t, 100.0, parsed.DMARC[0].PassRate)
	})

	t.Run("includes detailed fields when requested", func(t *testing.T) {
		result := &types.ParseResult{
			DMARCReports: []types.DMARCReport{
				{
					Domain:    "example.com",
					Breakdown: types.AuthBreakdown{SPFAndDKIM: 5},
					Sources: []types.Source{
						{IP: "1.2.3.4", Count: 5},
					},
				},
			},
		}

		jsonStr, err := ToJSON(result, true)
		require.NoError(t, err)

		var parsed JSONOutput
		err = json.Unmarshal([]byte(jsonStr), &parsed)
		require.NoError(t, err)

		require.NotNil(t, parsed.DMARC[0].Breakdown)
		assert.Equal(t, 5, parsed.DMARC[0].Breakdown.SPFAndDKIM)
		require.Len(t, parsed.DMARC[0].Sources, 1)
	})

	t.Run("omits detailed fields when not requested", func(t *testing.T) {
		result := &types.ParseResult{
			DMARCReports: []types.DMARCReport{
				{
					Domain:    "example.com",
					Breakdown: types.AuthBreakdown{SPFAndDKIM: 5},
				},
			},
		}

		jsonStr, err := ToJSON(result, false)
		require.NoError(t, err)

		// Check that breakdown is not in the JSON
		assert.NotContains(t, jsonStr, "breakdown")
	})
}

func TestToJSONWithInsights(t *testing.T) {
	t.Run("includes insights in output", func(t *testing.T) {
		result := &types.ParseResult{
			DMARCReports: []types.DMARCReport{
				{Domain: "example.com", TotalMessages: 100, Pass: 80, Fail: 20},
			},
		}

		insights := &analysis.InsightsResult{
			CriticalCount: 1,
			Insights: []analysis.Insight{
				{
					Severity:    analysis.SeverityCritical,
					Category:    analysis.CategoryAlignment,
					Domain:      "example.com",
					Title:       "Low DMARC pass rate",
					Description: "Only 80% pass rate",
					Suggestion:  "Review configuration",
				},
			},
		}

		jsonStr, err := ToJSONWithInsights(result, insights, false)
		require.NoError(t, err)

		var parsed JSONOutput
		err = json.Unmarshal([]byte(jsonStr), &parsed)
		require.NoError(t, err)

		require.NotNil(t, parsed.Insights)
		assert.Equal(t, 1, parsed.Insights.CriticalCount)
		require.Len(t, parsed.Insights.Items, 1)
		assert.Equal(t, "critical", parsed.Insights.Items[0].Severity)
		assert.Equal(t, "Low DMARC pass rate", parsed.Insights.Items[0].Title)
	})

	t.Run("handles nil insights", func(t *testing.T) {
		result := &types.ParseResult{
			DMARCReports: []types.DMARCReport{
				{Domain: "example.com"},
			},
		}

		jsonStr, err := ToJSONWithInsights(result, nil, false)
		require.NoError(t, err)

		assert.NotContains(t, jsonStr, "insights")
	})
}

func TestInsightsOutput(t *testing.T) {
	t.Run("renders insights with severity", func(t *testing.T) {
		insights := &analysis.InsightsResult{
			CriticalCount: 1,
			WarningCount:  1,
			Insights: []analysis.Insight{
				{
					Severity:    analysis.SeverityCritical,
					Category:    analysis.CategoryAlignment,
					Domain:      "example.com",
					Title:       "Critical issue",
					Description: "This is critical",
					Suggestion:  "Fix it now",
				},
				{
					Severity:    analysis.SeverityWarning,
					Category:    analysis.CategorySPF,
					Domain:      "example.com",
					Title:       "Warning issue",
					Description: "This is a warning",
				},
			},
		}

		output := InsightsOutput(insights, true)

		assert.Contains(t, output, "CRITICAL")
		assert.Contains(t, output, "WARNING")
		assert.Contains(t, output, "Critical issue")
		assert.Contains(t, output, "Warning issue")
		assert.Contains(t, output, "Fix it now")
	})

	t.Run("returns empty for no insights", func(t *testing.T) {
		insights := &analysis.InsightsResult{}

		output := InsightsOutput(insights, true)

		assert.Empty(t, output)
	})

	t.Run("shows summary counts", func(t *testing.T) {
		insights := &analysis.InsightsResult{
			CriticalCount: 2,
			WarningCount:  3,
			InfoCount:     1,
			Insights: []analysis.Insight{
				{Severity: analysis.SeverityCritical, Title: "Test"},
			},
		}

		output := InsightsOutput(insights, true)

		assert.Contains(t, output, "2 critical")
		assert.Contains(t, output, "3 warnings")
		assert.Contains(t, output, "1 info")
	})

	t.Run("shows hint when not detailed", func(t *testing.T) {
		insights := &analysis.InsightsResult{
			CriticalCount: 1,
			Insights: []analysis.Insight{
				{Severity: analysis.SeverityCritical, Title: "Test", Suggestion: "Fix it"},
			},
		}

		output := InsightsOutput(insights, false)

		assert.Contains(t, output, "1 critical")
		assert.Contains(t, output, "--detailed")
		assert.NotContains(t, output, "Test")
		assert.NotContains(t, output, "Fix it")
	})
}

func TestFormatRate(t *testing.T) {
	tests := []struct {
		rate     float64
		contains string
	}{
		{100.0, "100.0%"},
		{99.5, "99.5%"},
		{95.0, "95.0%"},
		{80.0, "80.0%"},
	}

	for _, tt := range tests {
		t.Run(tt.contains, func(t *testing.T) {
			result := formatRate(tt.rate)
			// Strip ANSI codes for comparison
			stripped := stripANSI(result)
			assert.Contains(t, stripped, strings.TrimSuffix(tt.contains, "%"))
		})
	}
}
