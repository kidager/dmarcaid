package parser

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kidager/dmarcaid/pkg/types"
)

func TestParseForensicBytes(t *testing.T) {
	t.Run("parses valid ARF report", func(t *testing.T) {
		data, err := os.ReadFile("testdata/forensic_sample.eml")
		require.NoError(t, err)

		report, err := ParseForensicBytes(data)
		require.NoError(t, err)
		require.NotNil(t, report)

		// Check basic fields
		assert.Equal(t, "example.com", report.Domain)
		assert.Equal(t, "example.com", report.ReportedDomain)
		assert.Equal(t, "192.0.2.1", report.SourceIP)
		assert.Equal(t, "auth-failure", report.FeedbackType)
		assert.Contains(t, report.UserAgent, "google.com")

		// Check auth results
		assert.Equal(t, "fail", report.SPFResult)
		assert.Equal(t, "fail", report.DKIMResult)
		assert.Equal(t, "fail", report.DMARCResult)

		// Check DKIM details
		assert.Equal(t, "example.com", report.DKIMDomain)
		assert.Equal(t, "selector1", report.DKIMSelector)

		// Check mail details
		assert.Equal(t, "attacker@malicious.com", report.OriginalMailFrom)
		assert.Equal(t, "victim@example.com", report.OriginalRcptTo)
		assert.Equal(t, "policy", report.DeliveryResult)

		// Check original headers
		assert.Equal(t, "Test Email Subject", report.Subject)
		assert.Equal(t, "<test123@example.com>", report.MessageID)
		assert.Contains(t, report.OriginalHeaders, "From")
		assert.Contains(t, report.OriginalHeaders, "To")

		// Check reporter
		require.Len(t, report.Reporters, 1)
		assert.Equal(t, "dmarc@google.com", report.Reporters[0])

		// Check arrival date
		assert.False(t, report.ArrivalDate.IsZero())
	})

	t.Run("handles minimal ARF report", func(t *testing.T) {
		minimalARF := `From: reporter@example.org
To: dmarc@example.com
Content-Type: multipart/report; report-type=feedback-report; boundary="boundary123"

--boundary123
Content-Type: text/plain

Human readable part.

--boundary123
Content-Type: message/feedback-report

Feedback-Type: auth-failure
Reported-Domain: test.com
Source-IP: 10.0.0.1
Authentication-Results: example.org; dkim=pass; spf=fail; dmarc=fail

--boundary123--
`
		report, err := ParseForensicBytes([]byte(minimalARF))
		require.NoError(t, err)
		require.NotNil(t, report)

		assert.Equal(t, "test.com", report.Domain)
		assert.Equal(t, "10.0.0.1", report.SourceIP)
		assert.Equal(t, "pass", report.DKIMResult)
		assert.Equal(t, "fail", report.SPFResult)
		assert.Equal(t, "fail", report.DMARCResult)
	})

	t.Run("returns error for non-multipart message", func(t *testing.T) {
		plainEmail := `From: sender@example.com
To: recipient@example.com
Subject: Plain email
Content-Type: text/plain

This is not a multipart message.
`
		_, err := ParseForensicBytes([]byte(plainEmail))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "multipart")
	})

	t.Run("returns error for invalid email", func(t *testing.T) {
		_, err := ParseForensicBytes([]byte("not a valid email"))
		assert.Error(t, err)
	})

	t.Run("handles missing boundary", func(t *testing.T) {
		noBoundary := `From: sender@example.com
Content-Type: multipart/report; report-type=feedback-report

This should fail because there's no boundary.
`
		_, err := ParseForensicBytes([]byte(noBoundary))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "boundary")
	})
}

func TestParseFeedbackReport(t *testing.T) {
	t.Run("parses all feedback fields", func(t *testing.T) {
		feedbackData := `Feedback-Type: auth-failure
User-Agent: test-agent/1.0
Version: 1
Arrival-Date: Mon, 20 Jan 2026 10:00:00 -0000
Source-IP: 203.0.113.1
Reported-Domain: example.net
Authentication-Results: mx.example.com; dkim=fail (bad signature); spf=softfail; dmarc=fail
Original-Mail-From: spoofed@attacker.com
Original-Rcpt-To: user@example.net
DKIM-Domain: example.net
DKIM-Identity: @example.net
DKIM-Selector: s1
Delivery-Result: none
`
		report := &types.ForensicReport{
			OriginalHeaders: make(map[string]string),
		}
		parseFeedbackReport(report, []byte(feedbackData))

		assert.Equal(t, "auth-failure", report.FeedbackType)
		assert.Equal(t, "test-agent/1.0", report.UserAgent)
		assert.Equal(t, "203.0.113.1", report.SourceIP)
		assert.Equal(t, "example.net", report.ReportedDomain)
		assert.Equal(t, "spoofed@attacker.com", report.OriginalMailFrom)
		assert.Equal(t, "user@example.net", report.OriginalRcptTo)
		assert.Equal(t, "example.net", report.DKIMDomain)
		assert.Equal(t, "@example.net", report.DKIMIdentity)
		assert.Equal(t, "s1", report.DKIMSelector)
		assert.Equal(t, "none", report.DeliveryResult)
		assert.Equal(t, "fail", report.DKIMResult)
		assert.Equal(t, "softfail", report.SPFResult)
		assert.Equal(t, "fail", report.DMARCResult)
	})

	t.Run("handles RFC3339 date format", func(t *testing.T) {
		feedbackData := `Arrival-Date: 2026-01-20T10:00:00Z
Source-IP: 192.0.2.1
`
		report := &types.ForensicReport{
			OriginalHeaders: make(map[string]string),
		}
		parseFeedbackReport(report, []byte(feedbackData))

		expected := time.Date(2026, 1, 20, 10, 0, 0, 0, time.UTC)
		assert.Equal(t, expected, report.ArrivalDate)
	})
}

func TestParseAuthResults(t *testing.T) {
	tests := []struct {
		name        string
		authResults string
		spf         string
		dkim        string
		dmarc       string
	}{
		{
			name:        "all pass",
			authResults: "mx.example.com; dkim=pass; spf=pass; dmarc=pass",
			spf:         "pass",
			dkim:        "pass",
			dmarc:       "pass",
		},
		{
			name:        "all fail",
			authResults: "mx.example.com; dkim=fail; spf=fail; dmarc=fail",
			spf:         "fail",
			dkim:        "fail",
			dmarc:       "fail",
		},
		{
			name:        "with reasons in parentheses",
			authResults: "mx.example.com; dkim=fail (bad signature); spf=softfail (not authorized); dmarc=fail (policy)",
			spf:         "softfail",
			dkim:        "fail",
			dmarc:       "fail",
		},
		{
			name:        "mixed results",
			authResults: "google.com; dkim=pass; spf=neutral; dmarc=fail",
			spf:         "neutral",
			dkim:        "pass",
			dmarc:       "fail",
		},
		{
			name:        "extra whitespace",
			authResults: "  mx.example.com ;  dkim=pass ;  spf=pass ;  dmarc=pass  ",
			spf:         "pass",
			dkim:        "pass",
			dmarc:       "pass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &types.ForensicReport{}
			parseAuthResults(report, tt.authResults)

			assert.Equal(t, tt.spf, report.SPFResult)
			assert.Equal(t, tt.dkim, report.DKIMResult)
			assert.Equal(t, tt.dmarc, report.DMARCResult)
		})
	}
}

func TestParseOriginalMessage(t *testing.T) {
	t.Run("parses headers from full message", func(t *testing.T) {
		message := `From: sender@example.com
To: recipient@example.com
Subject: Test Subject Line
Date: Mon, 20 Jan 2026 10:00:00 -0000
Message-ID: <msg123@example.com>
MIME-Version: 1.0
Content-Type: text/plain

This is the message body.
`
		report := &types.ForensicReport{
			OriginalHeaders: make(map[string]string),
		}
		parseOriginalMessage(report, []byte(message))

		assert.Equal(t, "Test Subject Line", report.Subject)
		assert.Equal(t, "<msg123@example.com>", report.MessageID)
		assert.Equal(t, "sender@example.com", report.OriginalHeaders["From"])
		assert.Equal(t, "recipient@example.com", report.OriginalHeaders["To"])
	})

	t.Run("parses headers only format", func(t *testing.T) {
		headers := `From: sender@example.com
To: recipient@example.com
Subject: Headers Only
Message-ID: <headers-only@example.com>

`
		report := &types.ForensicReport{
			OriginalHeaders: make(map[string]string),
		}
		parseOriginalMessage(report, []byte(headers))

		assert.Equal(t, "Headers Only", report.Subject)
		assert.Equal(t, "<headers-only@example.com>", report.MessageID)
	})

	t.Run("handles continuation lines", func(t *testing.T) {
		headers := `Subject: This is a very long subject line
	that continues on the next line
	and even another line
Message-ID: <multi@example.com>

`
		report := &types.ForensicReport{
			OriginalHeaders: make(map[string]string),
		}
		parseOriginalMessage(report, []byte(headers))

		assert.Contains(t, report.Subject, "very long subject")
		assert.Contains(t, report.Subject, "continues")
		assert.Contains(t, report.Subject, "another line")
	})

	t.Run("sets arrival date from Date header if not set", func(t *testing.T) {
		message := `Date: Mon, 20 Jan 2026 10:00:00 -0000
Subject: Test

Body
`
		report := &types.ForensicReport{
			OriginalHeaders: make(map[string]string),
		}
		parseOriginalMessage(report, []byte(message))

		assert.False(t, report.ArrivalDate.IsZero())
	})
}

func TestParseFileForensic(t *testing.T) {
	t.Run("detects and parses forensic file", func(t *testing.T) {
		dmarc, tls, forensic, err := ParseFile("testdata/forensic_sample.eml")
		require.NoError(t, err)

		assert.Nil(t, dmarc, "should not return DMARC report for forensic file")
		assert.Nil(t, tls, "should not return TLS report for forensic file")
		assert.NotNil(t, forensic, "should return forensic report")
		assert.Equal(t, "example.com", forensic.Domain)
	})
}
