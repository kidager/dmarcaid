package parser

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDMARC(t *testing.T) {
	tests := []struct {
		name           string
		file           string
		wantDomain     string
		wantReporter   string
		wantMessages   int
		wantPass       int
		wantFail       int
		wantSPFAndDKIM int
		wantDKIMOnly   int
		wantSPFOnly    int
	}{
		{
			name:           "Google report with DKIM pass, SPF fail",
			file:           "testdata/dmarc_google.xml",
			wantDomain:     "example.com",
			wantReporter:   "google.com",
			wantMessages:   1,
			wantPass:       1,
			wantFail:       0,
			wantSPFAndDKIM: 0,
			wantDKIMOnly:   1,
			wantSPFOnly:    0,
		},
		{
			name:           "Microsoft report",
			file:           "testdata/dmarc_microsoft.xml",
			wantDomain:     "example.com",
			wantReporter:   "Enterprise Outlook",
			wantMessages:   1,
			wantPass:       1,
			wantFail:       0,
			wantSPFAndDKIM: 0,
			wantDKIMOnly:   1,
			wantSPFOnly:    0,
		},
		{
			name:           "Yahoo report with full pass",
			file:           "testdata/dmarc_yahoo.xml",
			wantDomain:     "example.com",
			wantReporter:   "Yahoo",
			wantMessages:   1,
			wantPass:       1,
			wantFail:       0,
			wantSPFAndDKIM: 1,
			wantDKIMOnly:   0,
			wantSPFOnly:    0,
		},
		{
			name:         "Google report for secondary domain",
			file:         "testdata/dmarc_google_org.xml",
			wantDomain:   "example.org",
			wantReporter: "google.com",
			wantMessages: 1,
			wantPass:     1,
			wantFail:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(tt.file)
			require.NoError(t, err, "failed to read test file")

			report, err := ParseDMARCBytes(data)
			require.NoError(t, err, "failed to parse DMARC report")

			assert.Equal(t, tt.wantDomain, report.Domain, "domain mismatch")
			assert.Len(t, report.Reporters, 1, "expected exactly one reporter")
			assert.Equal(t, tt.wantReporter, report.Reporters[0], "reporter mismatch")
			assert.Equal(t, tt.wantMessages, report.TotalMessages, "total messages mismatch")
			assert.Equal(t, tt.wantPass, report.Pass, "pass count mismatch")
			assert.Equal(t, tt.wantFail, report.Fail, "fail count mismatch")

			if tt.wantSPFAndDKIM > 0 || tt.wantDKIMOnly > 0 || tt.wantSPFOnly > 0 {
				assert.Equal(t, tt.wantSPFAndDKIM, report.Breakdown.SPFAndDKIM, "SPF+DKIM breakdown mismatch")
				assert.Equal(t, tt.wantDKIMOnly, report.Breakdown.DKIMOnly, "DKIM-only breakdown mismatch")
				assert.Equal(t, tt.wantSPFOnly, report.Breakdown.SPFOnly, "SPF-only breakdown mismatch")
			}
		})
	}
}

func TestParseDMARCInvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "invalid XML",
			input:   "not xml at all",
			wantErr: "parsing XML",
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: "parsing XML",
		},
		{
			name:    "HTML instead of XML",
			input:   "<html><body>Hello</body></html>",
			wantErr: "", // parses but won't have expected structure
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseDMARCBytes([]byte(tt.input))
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestParseDMARCEmptyFeedback(t *testing.T) {
	xml := `<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>test.com</org_name>
    <date_range><begin>1767225600</begin><end>1767311999</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>test.com</domain>
  </policy_published>
</feedback>`

	report, err := ParseDMARCBytes([]byte(xml))
	require.NoError(t, err, "should parse empty feedback without error")

	assert.Equal(t, "test.com", report.Domain)
	assert.Equal(t, 0, report.TotalMessages, "empty feedback should have 0 messages")
	assert.Empty(t, report.Sources, "empty feedback should have no sources")
	assert.Empty(t, report.Failures, "empty feedback should have no failures")
}
