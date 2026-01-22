package parser

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"time"

	"github.com/kidager/dmarcaid/pkg/types"
)

// ParseForensicBytes parses a DMARC forensic report from ARF format.
func ParseForensicBytes(data []byte) (*types.ForensicReport, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parsing email: %w", err)
	}

	contentType := msg.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("parsing content-type: %w", err)
	}

	// ARF reports are multipart/report with report-type=feedback-report
	if !strings.HasPrefix(mediaType, "multipart/") {
		return nil, fmt.Errorf("expected multipart message, got %s", mediaType)
	}

	boundary := params["boundary"]
	if boundary == "" {
		return nil, fmt.Errorf("no boundary in multipart message")
	}

	report := &types.ForensicReport{
		OriginalHeaders: make(map[string]string),
	}

	// Extract reporter from email headers
	if from := msg.Header.Get("From"); from != "" {
		addr, err := mail.ParseAddress(from)
		if err == nil {
			report.Reporters = []string{addr.Address}
		} else {
			report.Reporters = []string{from}
		}
	}

	mr := multipart.NewReader(msg.Body, boundary)
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading multipart: %w", err)
		}

		partType := part.Header.Get("Content-Type")
		mediaType, _, _ := mime.ParseMediaType(partType)

		partData, err := io.ReadAll(part)
		if err != nil {
			continue
		}

		switch mediaType {
		case "message/feedback-report":
			parseFeedbackReport(report, partData)
		case "message/rfc822", "text/rfc822-headers":
			parseOriginalMessage(report, partData)
		}
	}

	// Set domain from reported domain or DKIM domain
	if report.ReportedDomain != "" {
		report.Domain = report.ReportedDomain
	} else if report.DKIMDomain != "" {
		report.Domain = report.DKIMDomain
	}

	return report, nil
}

func parseFeedbackReport(report *types.ForensicReport, data []byte) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch key {
		case "feedback-type":
			report.FeedbackType = value
		case "user-agent":
			report.UserAgent = value
		case "arrival-date":
			if t, err := mail.ParseDate(value); err == nil {
				report.ArrivalDate = t
			} else if t, err := time.Parse(time.RFC3339, value); err == nil {
				report.ArrivalDate = t
			}
		case "source-ip":
			report.SourceIP = value
		case "reported-domain":
			report.ReportedDomain = value
		case "authentication-results":
			report.AuthResults = value
			parseAuthResults(report, value)
		case "original-mail-from":
			report.OriginalMailFrom = value
		case "original-rcpt-to":
			report.OriginalRcptTo = value
		case "dkim-domain":
			report.DKIMDomain = value
		case "dkim-identity":
			report.DKIMIdentity = value
		case "dkim-selector":
			report.DKIMSelector = value
		case "delivery-result":
			report.DeliveryResult = value
		}
	}
}

func parseAuthResults(report *types.ForensicReport, authResults string) {
	// Parse authentication results like:
	// example.com; dkim=fail; spf=pass; dmarc=fail
	parts := strings.Split(authResults, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "dkim="):
			report.DKIMResult = strings.TrimPrefix(part, "dkim=")
			// Handle dkim=fail (reason)
			if idx := strings.Index(report.DKIMResult, " "); idx > 0 {
				report.DKIMResult = report.DKIMResult[:idx]
			}
		case strings.HasPrefix(part, "spf="):
			report.SPFResult = strings.TrimPrefix(part, "spf=")
			if idx := strings.Index(report.SPFResult, " "); idx > 0 {
				report.SPFResult = report.SPFResult[:idx]
			}
		case strings.HasPrefix(part, "dmarc="):
			report.DMARCResult = strings.TrimPrefix(part, "dmarc=")
			if idx := strings.Index(report.DMARCResult, " "); idx > 0 {
				report.DMARCResult = report.DMARCResult[:idx]
			}
		}
	}
}

func parseOriginalMessage(report *types.ForensicReport, data []byte) {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		// Try parsing as just headers
		parseHeadersOnly(report, data)
		return
	}

	// Extract useful headers
	if subject := msg.Header.Get("Subject"); subject != "" {
		report.Subject = subject
		report.OriginalHeaders["Subject"] = subject
	}
	if msgID := msg.Header.Get("Message-ID"); msgID != "" {
		report.MessageID = msgID
		report.OriginalHeaders["Message-ID"] = msgID
	}
	if from := msg.Header.Get("From"); from != "" {
		report.OriginalHeaders["From"] = from
	}
	if to := msg.Header.Get("To"); to != "" {
		report.OriginalHeaders["To"] = to
	}
	if date := msg.Header.Get("Date"); date != "" {
		report.OriginalHeaders["Date"] = date
	}

	// If we don't have arrival date from feedback report, use Date header
	if report.ArrivalDate.IsZero() {
		if dateStr := msg.Header.Get("Date"); dateStr != "" {
			if t, err := mail.ParseDate(dateStr); err == nil {
				report.ArrivalDate = t
			}
		}
	}
}

func parseHeadersOnly(report *types.ForensicReport, data []byte) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var currentKey string
	var currentValue strings.Builder

	saveHeader := func() {
		if currentKey != "" {
			value := strings.TrimSpace(currentValue.String())
			report.OriginalHeaders[currentKey] = value
			switch strings.ToLower(currentKey) {
			case "subject":
				report.Subject = value
			case "message-id":
				report.MessageID = value
			}
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break // End of headers
		}

		// Continuation line (starts with whitespace)
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			currentValue.WriteString(" ")
			currentValue.WriteString(strings.TrimSpace(line))
			continue
		}

		// New header
		saveHeader()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			currentKey = strings.TrimSpace(parts[0])
			currentValue.Reset()
			currentValue.WriteString(strings.TrimSpace(parts[1]))
		}
	}
	saveHeader()
}
