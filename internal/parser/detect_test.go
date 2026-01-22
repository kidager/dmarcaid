package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectFileType(t *testing.T) {
	tests := []struct {
		path     string
		expected FileType
	}{
		// DMARC XML variants
		{"report.xml", FileTypeDMARCXML},
		{"report.XML", FileTypeDMARCXML},
		{"/path/to/google.com!example.com!123.xml", FileTypeDMARCXML},

		// DMARC Gzip variants
		{"report.xml.gz", FileTypeDMARCGzip},
		{"report.XML.GZ", FileTypeDMARCGzip},

		// DMARC Zip variants
		{"report.zip", FileTypeDMARCZip},
		{"report.ZIP", FileTypeDMARCZip},

		// TLS-RPT JSON variants
		{"report.json", FileTypeTLSJSON},
		{"report.JSON", FileTypeTLSJSON},

		// TLS-RPT Gzip variants
		{"report.json.gz", FileTypeTLSGzip},
		{"report.JSON.GZ", FileTypeTLSGzip},

		// Forensic EML variants
		{"report.eml", FileTypeForensicEML},
		{"report.EML", FileTypeForensicEML},
		{"/path/to/forensic_report.eml", FileTypeForensicEML},

		// Unknown types
		{"report.txt", FileTypeUnknown},
		{"report", FileTypeUnknown},
		{"report.pdf", FileTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := DetectFileType(tt.path)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestDetectContentType(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected ContentType
	}{
		{
			name:     "DMARC feedback XML",
			data:     `<?xml version="1.0"?><feedback><report_metadata></report_metadata></feedback>`,
			expected: ContentTypeDMARC,
		},
		{
			name:     "DMARC feedback with whitespace",
			data:     `  <?xml version="1.0"?><feedback></feedback>  `,
			expected: ContentTypeDMARC,
		},
		{
			name:     "TLS-RPT JSON",
			data:     `{"organization-name": "google.com", "policies": []}`,
			expected: ContentTypeTLSRPT,
		},
		{
			name:     "TLS-RPT JSON with whitespace",
			data:     `  {"organization-name": "test.com"}  `,
			expected: ContentTypeTLSRPT,
		},
		{
			name:     "random text",
			data:     `random text that is not a report`,
			expected: ContentTypeUnknown,
		},
		{
			name:     "empty input",
			data:     ``,
			expected: ContentTypeUnknown,
		},
		{
			name:     "XML but not DMARC",
			data:     `<html><body>Not DMARC</body></html>`,
			expected: ContentTypeUnknown,
		},
		{
			name:     "JSON but not TLS-RPT",
			data:     `{"name": "test", "value": 123}`,
			expected: ContentTypeUnknown,
		},
		{
			name: "Forensic ARF report",
			data: `Content-Type: multipart/report; report-type=feedback-report; boundary="123"

--123
Content-Type: text/plain

This is a DMARC failure report.
--123--`,
			expected: ContentTypeForensic,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectContentType([]byte(tt.data))
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestParseFile(t *testing.T) {
	t.Run("DMARC XML file", func(t *testing.T) {
		dmarc, tls, forensic, err := ParseFile("testdata/dmarc_google.xml")
		require.NoError(t, err)

		assert.NotNil(t, dmarc, "should return DMARC report")
		assert.Nil(t, tls, "should not return TLS report for DMARC file")
		assert.Nil(t, forensic, "should not return forensic report for DMARC file")
		assert.Equal(t, "example.com", dmarc.Domain)
	})

	t.Run("TLS-RPT JSON file", func(t *testing.T) {
		dmarc, tls, forensic, err := ParseFile("testdata/tlsrpt_google.json")
		require.NoError(t, err)

		assert.Nil(t, dmarc, "should not return DMARC report for TLS file")
		assert.NotNil(t, tls, "should return TLS report")
		assert.Nil(t, forensic, "should not return forensic report for TLS file")
		assert.Equal(t, "example.com", tls.Domain)
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, _, _, err := ParseFile("testdata/does_not_exist.xml")
		assert.Error(t, err)
	})
}
