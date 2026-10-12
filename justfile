# dmarcaid - DMARC & TLS-RPT Report Analyzer

set shell := ["bash", "-cu"]

version := `git describe --tags --always --dirty 2>/dev/null || echo "dev"`
commit := `git rev-parse --short HEAD 2>/dev/null || echo "none"`
build_date := `date -u +"%Y-%m-%dT%H:%M:%SZ"`
ldflags := "-X github.com/kidager/dmarcaid/internal/cmd.Version=" + version + " -X github.com/kidager/dmarcaid/internal/cmd.Commit=" + commit + " -X github.com/kidager/dmarcaid/internal/cmd.BuildDate=" + build_date

# List available commands
default:
    @just --list

# Build the binary
build:
    go build -ldflags '{{ldflags}}' -o dmarcaid ./cmd/dmarcaid

# Build for all platforms
build-all: build-linux build-darwin build-windows

# Build for Linux (amd64 and arm64)
build-linux:
    GOOS=linux GOARCH=amd64 go build -ldflags '{{ldflags}}' -o dist/dmarcaid-linux-amd64 ./cmd/dmarcaid
    GOOS=linux GOARCH=arm64 go build -ldflags '{{ldflags}}' -o dist/dmarcaid-linux-arm64 ./cmd/dmarcaid

# Build for macOS (amd64 and arm64)
build-darwin:
    GOOS=darwin GOARCH=amd64 go build -ldflags '{{ldflags}}' -o dist/dmarcaid-darwin-amd64 ./cmd/dmarcaid
    GOOS=darwin GOARCH=arm64 go build -ldflags '{{ldflags}}' -o dist/dmarcaid-darwin-arm64 ./cmd/dmarcaid

# Build for Windows
build-windows:
    GOOS=windows GOARCH=amd64 go build -ldflags '{{ldflags}}' -o dist/dmarcaid-windows-amd64.exe ./cmd/dmarcaid

# Install to GOPATH/bin
install:
    go install -ldflags '{{ldflags}}' ./cmd/dmarcaid

# Run tests
test:
    go test -v ./...

# Run tests with coverage
test-cover:
    go test -v -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html

# Run linter
lint:
    golangci-lint run

# Format code
fmt:
    go fmt ./...
    gofumpt -l -w .

# Tidy dependencies
tidy:
    go mod tidy

# Clean build artifacts
clean:
    rm -f dmarcaid
    rm -rf dist/
    rm -f coverage.out coverage.html
    go clean

# Run the app (for development)
run *ARGS:
    go run ./cmd/dmarcaid {{ARGS}}

# Check for outdated dependencies
outdated:
    go list -u -m all

# Setup development environment (install pre-commit hooks)
setup:
    pre-commit install

# Run pre-commit on all files
pre-commit:
    pre-commit run --all-files
