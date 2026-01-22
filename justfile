# dmarcade - DMARC & TLS-RPT Report Analyzer

set shell := ["bash", "-cu"]

version := `git describe --tags --always --dirty 2>/dev/null || echo "dev"`
commit := `git rev-parse --short HEAD 2>/dev/null || echo "none"`
build_date := `date -u +"%Y-%m-%dT%H:%M:%SZ"`
ldflags := "-X github.com/kidager/dmarcade/internal/cmd.Version=" + version + " -X github.com/kidager/dmarcade/internal/cmd.Commit=" + commit + " -X github.com/kidager/dmarcade/internal/cmd.BuildDate=" + build_date

# List available commands
default:
    @just --list

# Build the binary
build:
    go build -ldflags '{{ldflags}}' -o dmarcade ./cmd/dmarcade

# Build for all platforms
build-all: build-linux build-darwin build-windows

# Build for Linux (amd64 and arm64)
build-linux:
    GOOS=linux GOARCH=amd64 go build -ldflags '{{ldflags}}' -o dist/dmarcade-linux-amd64 ./cmd/dmarcade
    GOOS=linux GOARCH=arm64 go build -ldflags '{{ldflags}}' -o dist/dmarcade-linux-arm64 ./cmd/dmarcade

# Build for macOS (amd64 and arm64)
build-darwin:
    GOOS=darwin GOARCH=amd64 go build -ldflags '{{ldflags}}' -o dist/dmarcade-darwin-amd64 ./cmd/dmarcade
    GOOS=darwin GOARCH=arm64 go build -ldflags '{{ldflags}}' -o dist/dmarcade-darwin-arm64 ./cmd/dmarcade

# Build for Windows
build-windows:
    GOOS=windows GOARCH=amd64 go build -ldflags '{{ldflags}}' -o dist/dmarcade-windows-amd64.exe ./cmd/dmarcade

# Install to GOPATH/bin
install:
    go install -ldflags '{{ldflags}}' ./cmd/dmarcade

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
    rm -f dmarcade
    rm -rf dist/
    rm -f coverage.out coverage.html
    go clean

# Run the app (for development)
run *ARGS:
    go run ./cmd/dmarcade {{ARGS}}

# Check for outdated dependencies
outdated:
    go list -u -m all

# Setup development environment (install pre-commit hooks)
setup:
    pre-commit install

# Run pre-commit on all files
pre-commit:
    pre-commit run --all-files
