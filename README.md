# 💊 dmarcaid

> Version <!-- x-release-please-version -->0.0.0<!-- x-release-please-end -->

A fast, modern CLI tool for parsing and analyzing DMARC, TLS-RPT, and DMARC forensic reports.

## Features

- **Multi-format support**: Parse DMARC aggregate (RUA), TLS-RPT, and DMARC forensic (RUF) reports
- **File format detection**: Automatically handles XML, JSON, gzip, zip, and EML files
- **Domain aggregation**: Combine multiple reports by domain for comprehensive analysis
- **Insights engine**: Get actionable recommendations based on your email authentication data
- **Beautiful output**: Styled terminal tables with color-coded pass/fail indicators
- **JSON export**: Machine-readable output for scripting and automation
- **Shell completion**: Tab completion for Bash, Zsh, Fish, and PowerShell

## Installation

### Homebrew (macOS/Linux)

```bash
brew install --cask kidager/tap/dmarcaid
```

#### macOS Gatekeeper

On macOS, you may see a warning that the binary "cannot be verified". This is because the binary is not signed with an Apple Developer certificate. To allow it to run:

```bash
xattr -d com.apple.quarantine $(which dmarcaid)
```

### Go Install

```bash
go install github.com/kidager/dmarcaid@latest
```

### Download Binary

Download pre-built binaries from the [releases page](https://github.com/kidager/dmarcaid/releases).

## Usage

### Parse Reports

```bash
# Parse a single report
dmarcaid parse report.xml

# Parse multiple files
dmarcaid parse report1.xml report2.json.gz forensic.eml

# Parse all reports in a directory
dmarcaid parse ./reports/

# Show detailed output
dmarcaid parse ./reports/ --detailed

# Output as JSON
dmarcaid parse ./reports/ --json

# Filter by domain
dmarcaid parse ./reports/ --domain example.com

# Filter by status
dmarcaid parse ./reports/ --status fail
```

### Output Example

```
DMARC Report Analysis

Parsed 5 files: 3 DMARC, 1 TLS-RPT, 1 Forensic

DMARC Reports
Domain                    Messages   Pass     Fail     Rate     Reporters
example.com               1000       980      20       98.0%    google.com, microsoft.com

TLS-RPT Reports
Domain                    Sessions   Success  Failure  Rate     Reporters
example.com               500        498      2        99.6%    google.com

Forensic Reports (DMARC Failures)
Domain                    Source IP        SPF      DKIM     DMARC    Reporter
example.com               192.0.2.1        fail     fail     fail     google.com

Insights
Found 1 warning, 2 info
```

### Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--detailed` | `-d` | Show detailed output with all records |
| `--insights` | `-i` | Show insights and recommendations (default: true) |
| `--json` | | Output results as JSON |
| `--domain` | | Filter results by domain |
| `--status` | | Filter by status (pass, fail) |
| `--ip` | | Filter by source IP |

## Shell Completion

dmarcaid supports shell completion for Bash, Zsh, Fish, and PowerShell.

### Bash

```bash
# Load completion for current session
source <(dmarcaid completion bash)

# Install permanently (Linux)
dmarcaid completion bash > /etc/bash_completion.d/dmarcaid

# Install permanently (macOS with Homebrew)
dmarcaid completion bash > $(brew --prefix)/etc/bash_completion.d/dmarcaid
```

### Zsh

```zsh
# Enable completion (add to ~/.zshrc if not already enabled)
autoload -U compinit; compinit

# Install completion
dmarcaid completion zsh > "${fpath[1]}/_dmarcaid"

# Restart your shell or run: compinit
```

### Fish

```fish
# Load completion for current session
dmarcaid completion fish | source

# Install permanently
dmarcaid completion fish > ~/.config/fish/completions/dmarcaid.fish
```

### PowerShell

```powershell
# Load completion for current session
dmarcaid completion powershell | Out-String | Invoke-Expression

# Install permanently (add to your PowerShell profile)
dmarcaid completion powershell > dmarcaid.ps1
# Then source the file from your profile
```

## Supported Report Types

### DMARC Aggregate Reports (RUA)

XML format reports sent by email receivers containing:
- Authentication results (SPF, DKIM, DMARC)
- Source IP statistics
- Policy disposition outcomes

### TLS-RPT Reports

JSON format reports containing:
- TLS session success/failure counts
- Failure type breakdowns
- MTA-STS policy compliance

### DMARC Forensic Reports (RUF)

ARF (Abuse Reporting Format) messages containing:
- Individual message failure details
- Original message headers
- Authentication failure specifics

## Building from Source

### Requirements

- Go 1.21 or later

### Build

```bash
# Clone the repository
git clone https://github.com/kidager/dmarcaid.git
cd dmarcaid

# Build
go build -o dmarcaid ./cmd/dmarcaid

# Run tests
go test ./...

# Run linter
golangci-lint run
```

### Development

```bash
# Install development tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run tests with coverage
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Build with version info
go build -ldflags "-X github.com/kidager/dmarcaid/internal/cmd.Version=dev" -o dmarcaid ./cmd/dmarcaid
```

## License

This project is released into the public domain under [The Unlicense](LICENSE).
