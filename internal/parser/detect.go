package parser

// File detection and decompression utilities for DMARC and TLS-RPT reports.

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kidager/dmarcaid/pkg/types"
)

// FileType represents the type of report file.
type FileType int

// Supported file types for report parsing.
const (
	FileTypeUnknown     FileType = iota // Unknown or unsupported file type
	FileTypeDMARCXML                    // Plain XML DMARC report
	FileTypeDMARCGzip                   // Gzip-compressed XML DMARC report
	FileTypeDMARCZip                    // Zip-archived XML DMARC report
	FileTypeTLSJSON                     // Plain JSON TLS-RPT report
	FileTypeTLSGzip                     // Gzip-compressed JSON TLS-RPT report
	FileTypeForensicEML                 // DMARC forensic report (ARF format)
)

// ContentType represents the detected content type of report data.
type ContentType string

// Content type identifiers returned by detectContentType.
const (
	ContentTypeDMARC    ContentType = "dmarc"
	ContentTypeTLSRPT   ContentType = "tlsrpt"
	ContentTypeForensic ContentType = "forensic"
	ContentTypeUnknown  ContentType = "unknown"
)

// ParseFile parses a report file and returns the appropriate report type.
func ParseFile(path string) (*types.DMARCReport, *types.TLSReport, *types.ForensicReport, error) {
	fileType := DetectFileType(path)

	data, err := ReadFile(path, fileType)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading file: %w", err)
	}

	contentType := detectContentType(data)

	switch contentType {
	case ContentTypeDMARC:
		report, err := ParseDMARCBytes(data)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parsing DMARC: %w", err)
		}
		return report, nil, nil, nil
	case ContentTypeTLSRPT:
		report, err := ParseTLSRPTBytes(data)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parsing TLS-RPT: %w", err)
		}
		return nil, report, nil, nil
	case ContentTypeForensic:
		report, err := ParseForensicBytes(data)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parsing forensic: %w", err)
		}
		return nil, nil, report, nil
	default:
		return nil, nil, nil, errors.New("unknown file format")
	}
}

// DetectFileType determines the file type based on extension.
func DetectFileType(path string) FileType {
	lower := strings.ToLower(path)

	switch {
	case strings.HasSuffix(lower, ".xml.gz"):
		return FileTypeDMARCGzip
	case strings.HasSuffix(lower, ".xml"):
		return FileTypeDMARCXML
	case strings.HasSuffix(lower, ".zip"):
		return FileTypeDMARCZip
	case strings.HasSuffix(lower, ".json.gz"):
		return FileTypeTLSGzip
	case strings.HasSuffix(lower, ".json"):
		return FileTypeTLSJSON
	case strings.HasSuffix(lower, ".eml"):
		return FileTypeForensicEML
	default:
		return FileTypeUnknown
	}
}

// ReadFile reads and decompresses a file based on its type.
func ReadFile(path string, fileType FileType) ([]byte, error) {
	switch fileType {
	case FileTypeDMARCXML, FileTypeTLSJSON, FileTypeForensicEML:
		return os.ReadFile(path)
	case FileTypeDMARCGzip, FileTypeTLSGzip:
		return readGzipFile(path)
	case FileTypeDMARCZip:
		return readZipFile(path)
	case FileTypeUnknown:
		return readAndDetect(path)
	default:
		return nil, fmt.Errorf("unsupported file type: %s", path)
	}
}

func readGzipFile(path string) (data []byte, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("creating gzip reader: %w", err)
	}
	defer func() {
		if cerr := gr.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	return io.ReadAll(gr)
}

func readZipFile(path string) (data []byte, err error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("opening zip: %w", err)
	}
	defer func() {
		if cerr := zr.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	for _, f := range zr.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".xml") {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("opening zip entry: %w", err)
			}
			data, err = io.ReadAll(rc)
			if cerr := rc.Close(); cerr != nil && err == nil {
				err = cerr
			}
			return data, err
		}
	}

	return nil, errors.New("no XML file found in zip archive")
}

func readAndDetect(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Check for gzip magic number
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		return decompressGzip(data)
	}

	// Check for zip magic number
	if len(data) >= 4 && data[0] == 0x50 && data[1] == 0x4b && data[2] == 0x03 && data[3] == 0x04 {
		return extractFromZip(data)
	}

	return data, nil
}

func decompressGzip(data []byte) (result []byte, err error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating gzip reader: %w", err)
	}
	defer func() {
		if cerr := gr.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	return io.ReadAll(gr)
}

func extractFromZip(data []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("creating zip reader: %w", err)
	}
	for _, f := range zr.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".xml") {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("opening zip entry: %w", err)
			}
			result, err := io.ReadAll(rc)
			if cerr := rc.Close(); cerr != nil && err == nil {
				err = cerr
			}
			return result, err
		}
	}
	return nil, errors.New("no XML file found in zip archive")
}

// detectContentType determines if the content is DMARC XML, TLS-RPT JSON, or forensic ARF.
func detectContentType(data []byte) ContentType {
	trimmed := bytes.TrimSpace(data)

	// Check for XML (DMARC aggregate report)
	if len(trimmed) > 0 && trimmed[0] == '<' {
		var feedback struct {
			XMLName xml.Name `xml:"feedback"`
		}
		if xml.Unmarshal(trimmed, &feedback) == nil && feedback.XMLName.Local == "feedback" {
			return ContentTypeDMARC
		}
	}

	// Check for JSON (TLS-RPT)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		var tlsCheck struct {
			OrganizationName string `json:"organization-name"`
		}
		if json.Unmarshal(trimmed, &tlsCheck) == nil && tlsCheck.OrganizationName != "" {
			return ContentTypeTLSRPT
		}
	}

	// Check for ARF (DMARC forensic report)
	// ARF messages have Content-Type: multipart/report; report-type=feedback-report
	dataStr := string(data)
	if strings.Contains(dataStr, "Content-Type:") &&
		strings.Contains(dataStr, "multipart/report") &&
		strings.Contains(dataStr, "feedback-report") {
		return ContentTypeForensic
	}

	return ContentTypeUnknown
}

// WalkDirectory walks a directory and returns all report files.
func WalkDirectory(root string) ([]string, error) {
	var files []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		ft := DetectFileType(path)
		if ft != FileTypeUnknown {
			files = append(files, path)
			return nil
		}

		// For unknown extensions, check if it might be a report file
		ext := strings.ToLower(filepath.Ext(path))
		if ext == "" || ext == ".gz" || ext == ".eml" {
			files = append(files, path)
		}

		return nil
	})

	return files, err
}
