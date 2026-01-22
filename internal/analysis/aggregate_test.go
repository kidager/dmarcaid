package analysis

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kidager/dmarcaid/pkg/types"
)

func TestAggregate(t *testing.T) {
	t.Run("aggregates multiple DMARC reports for same domain", func(t *testing.T) {
		result := &types.ParseResult{
			DMARCReports: []types.DMARCReport{
				{
					Domain:        "example.com",
					Reporters:     []string{"google.com"},
					TotalMessages: 10,
					Pass:          8,
					Fail:          2,
					Period:        types.Period{Begin: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 1, 1, 23, 59, 59, 0, time.UTC)},
					Breakdown:     types.AuthBreakdown{SPFAndDKIM: 5, DKIMOnly: 3},
				},
				{
					Domain:        "example.com",
					Reporters:     []string{"yahoo.com"},
					TotalMessages: 5,
					Pass:          5,
					Fail:          0,
					Period:        types.Period{Begin: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 1, 2, 23, 59, 59, 0, time.UTC)},
					Breakdown:     types.AuthBreakdown{SPFAndDKIM: 5},
				},
			},
		}

		agg := Aggregate(result)

		require.Len(t, agg.DMARC, 1, "should aggregate into single domain")
		d := agg.DMARC["example.com"]
		assert.Equal(t, 2, d.ReportCount, "report count")
		assert.Equal(t, 15, d.TotalMessages, "total messages")
		assert.Equal(t, 13, d.Pass, "pass count")
		assert.Equal(t, 2, d.Fail, "fail count")
		assert.Equal(t, 10, d.Breakdown.SPFAndDKIM, "SPF+DKIM breakdown")
		assert.Equal(t, 3, d.Breakdown.DKIMOnly, "DKIM-only breakdown")
		assert.Len(t, d.Reporters, 2, "unique reporters")
	})

	t.Run("keeps separate domains separate", func(t *testing.T) {
		result := &types.ParseResult{
			DMARCReports: []types.DMARCReport{
				{Domain: "example.com", TotalMessages: 10, Pass: 10},
				{Domain: "example.org", TotalMessages: 5, Pass: 5},
			},
		}

		agg := Aggregate(result)

		assert.Len(t, agg.DMARC, 2, "should have two domains")
		assert.Equal(t, 10, agg.DMARC["example.com"].TotalMessages)
		assert.Equal(t, 5, agg.DMARC["example.org"].TotalMessages)
	})

	t.Run("aggregates TLS reports", func(t *testing.T) {
		result := &types.ParseResult{
			TLSReports: []types.TLSReport{
				{Domain: "example.com", Reporters: []string{"google.com"}, TotalSessions: 100, Success: 95, Failure: 5},
				{Domain: "example.com", Reporters: []string{"microsoft.com"}, TotalSessions: 50, Success: 48, Failure: 2},
			},
		}

		agg := Aggregate(result)

		require.Len(t, agg.TLSRPT, 1)
		tlsAgg := agg.TLSRPT["example.com"]
		assert.Equal(t, 150, tlsAgg.TotalSessions)
		assert.Equal(t, 143, tlsAgg.Success)
		assert.Equal(t, 7, tlsAgg.Failure)
	})

	t.Run("calculates pass rate correctly", func(t *testing.T) {
		result := &types.ParseResult{
			DMARCReports: []types.DMARCReport{
				{Domain: "example.com", TotalMessages: 100, Pass: 90, Fail: 10},
			},
		}

		agg := Aggregate(result)

		assert.InDelta(t, 90.0, agg.DMARC["example.com"].PassRate, 0.1)
	})

	t.Run("aggregates sources correctly", func(t *testing.T) {
		result := &types.ParseResult{
			DMARCReports: []types.DMARCReport{
				{
					Domain: "example.com",
					Sources: []types.Source{
						{IP: "1.2.3.4", Count: 10, SPFResult: "pass", DKIMResult: "pass"},
					},
				},
				{
					Domain: "example.com",
					Sources: []types.Source{
						{IP: "1.2.3.4", Count: 5, SPFResult: "pass", DKIMResult: "fail"},
					},
				},
			},
		}

		agg := Aggregate(result)

		d := agg.DMARC["example.com"]
		require.Len(t, d.SourcesList, 1, "should aggregate same IP")
		assert.Equal(t, 15, d.SourcesList[0].Count)
	})

	t.Run("tracks period bounds", func(t *testing.T) {
		result := &types.ParseResult{
			DMARCReports: []types.DMARCReport{
				{
					Domain: "example.com",
					Period: types.Period{
						Begin: time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC),
						End:   time.Date(2026, 1, 5, 23, 59, 59, 0, time.UTC),
					},
				},
				{
					Domain: "example.com",
					Period: types.Period{
						Begin: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
						End:   time.Date(2026, 1, 10, 23, 59, 59, 0, time.UTC),
					},
				},
			},
		}

		agg := Aggregate(result)

		d := agg.DMARC["example.com"]
		assert.Equal(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), d.PeriodStart)
		assert.Equal(t, time.Date(2026, 1, 10, 23, 59, 59, 0, time.UTC), d.PeriodEnd)
	})
}

func TestAggregatedResultToParseResult(t *testing.T) {
	t.Run("converts back to ParseResult format", func(t *testing.T) {
		result := &types.ParseResult{
			DMARCReports: []types.DMARCReport{
				{Domain: "example.com", Reporters: []string{"google.com"}, TotalMessages: 10, Pass: 10},
				{Domain: "example.com", Reporters: []string{"yahoo.com"}, TotalMessages: 5, Pass: 5},
			},
			TLSReports: []types.TLSReport{
				{Domain: "example.com", TotalSessions: 100, Success: 100},
			},
		}

		agg := Aggregate(result)
		converted := agg.ToParseResult()

		require.Len(t, converted.DMARCReports, 1)
		assert.Equal(t, "example.com", converted.DMARCReports[0].Domain)
		assert.Equal(t, 15, converted.DMARCReports[0].TotalMessages)
		assert.Len(t, converted.DMARCReports[0].Reporters, 2)

		require.Len(t, converted.TLSReports, 1)
		assert.Equal(t, 100, converted.TLSReports[0].TotalSessions)
	})

	t.Run("sorts results by domain", func(t *testing.T) {
		result := &types.ParseResult{
			DMARCReports: []types.DMARCReport{
				{Domain: "zebra.com", TotalMessages: 1},
				{Domain: "alpha.com", TotalMessages: 1},
				{Domain: "beta.com", TotalMessages: 1},
			},
		}

		agg := Aggregate(result)
		converted := agg.ToParseResult()

		require.Len(t, converted.DMARCReports, 3)
		assert.Equal(t, "alpha.com", converted.DMARCReports[0].Domain)
		assert.Equal(t, "beta.com", converted.DMARCReports[1].Domain)
		assert.Equal(t, "zebra.com", converted.DMARCReports[2].Domain)
	})
}

func TestAggregateSummary(t *testing.T) {
	t.Run("calculates overall statistics", func(t *testing.T) {
		result := &types.ParseResult{
			DMARCReports: []types.DMARCReport{
				{Domain: "a.com", TotalMessages: 100, Pass: 90, Fail: 10},
				{Domain: "b.com", TotalMessages: 50, Pass: 50},
			},
			TLSReports: []types.TLSReport{
				{Domain: "a.com", TotalSessions: 200, Success: 190, Failure: 10},
			},
		}

		agg := Aggregate(result)

		assert.Equal(t, 2, agg.Summary.TotalDomains)
		assert.Equal(t, 2, agg.Summary.TotalDMARCReports)
		assert.Equal(t, 1, agg.Summary.TotalTLSReports)
		assert.Equal(t, 150, agg.Summary.TotalMessages)
		assert.Equal(t, 200, agg.Summary.TotalSessions)
		assert.InDelta(t, 93.3, agg.Summary.OverallPassRate, 0.1)
		assert.InDelta(t, 95.0, agg.Summary.OverallTLSRate, 0.1)
	})
}
