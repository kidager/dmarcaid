package parser

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTLSRPT(t *testing.T) {
	t.Run("Google TLS-RPT report", func(t *testing.T) {
		data, err := os.ReadFile("testdata/tlsrpt_google.json")
		require.NoError(t, err, "failed to read test file")

		report, err := ParseTLSRPTBytes(data)
		require.NoError(t, err, "failed to parse TLS-RPT report")

		assert.Equal(t, "example.com", report.Domain)
		assert.Equal(t, []string{"Google Inc."}, report.Reporters)

		expectedBegin := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		assert.Equal(t, expectedBegin, report.Period.Begin, "period begin mismatch")

		assert.Equal(t, 1, report.TotalSessions, "total sessions mismatch")
		assert.Equal(t, 1, report.Success, "success count mismatch")
		assert.Equal(t, 0, report.Failure, "failure count mismatch")
		assert.Empty(t, report.Failures, "should have no failure details")
	})
}

func TestParseTLSRPTWithFailures(t *testing.T) {
	json := `{
		"organization-name": "Example Org",
		"date-range": {
			"start-datetime": "2026-01-01T00:00:00Z",
			"end-datetime": "2026-01-01T23:59:59Z"
		},
		"policies": [{
			"policy": {
				"policy-type": "sts",
				"policy-domain": "example.com"
			},
			"summary": {
				"total-successful-session-count": 100,
				"total-failure-session-count": 5
			},
			"failure-details": [{
				"result-type": "certificate-expired",
				"sending-mta-ip": "12.34.56.78",
				"receiving-mx-hostname": "mail.example.com",
				"failed-session-count": 3
			}, {
				"result-type": "starttls-not-supported",
				"sending-mta-ip": "12.34.56.79",
				"receiving-mx-hostname": "mail2.example.com",
				"failed-session-count": 2
			}]
		}]
	}`

	report, err := ParseTLSRPTBytes([]byte(json))
	require.NoError(t, err)

	assert.Equal(t, "example.com", report.Domain)
	assert.Equal(t, 105, report.TotalSessions, "total = success + failure")
	assert.Equal(t, 100, report.Success)
	assert.Equal(t, 5, report.Failure)

	require.Len(t, report.Failures, 2, "should have 2 failure details")

	assert.Equal(t, "certificate-expired", report.Failures[0].Type)
	assert.Equal(t, 3, report.Failures[0].Count)
	assert.Equal(t, "mail.example.com", report.Failures[0].ReceivingMTA)

	assert.Equal(t, "starttls-not-supported", report.Failures[1].Type)
	assert.Equal(t, 2, report.Failures[1].Count)
}

func TestParseTLSRPTInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "invalid JSON", input: "not json"},
		{name: "empty string", input: ""},
		{name: "XML instead of JSON", input: "<xml/>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseTLSRPTBytes([]byte(tt.input))
			assert.Error(t, err, "should fail to parse invalid input")
		})
	}
}

func TestParseTLSRPTEmptyPolicies(t *testing.T) {
	json := `{
		"organization-name": "test.com",
		"date-range": {
			"start-datetime": "2026-01-01T00:00:00Z",
			"end-datetime": "2026-01-01T23:59:59Z"
		},
		"policies": []
	}`

	report, err := ParseTLSRPTBytes([]byte(json))
	require.NoError(t, err)

	assert.Equal(t, 0, report.TotalSessions, "empty policies = 0 sessions")
	assert.Empty(t, report.Failures)
}
