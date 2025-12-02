# Pentakit

Pentakit is an extensible **Go-based penetration testing toolkit**.
It provides a modular CLI and an interactive TUI (`--tui`) to automate repeatable pentest workflows such as reconnaissance, enumeration, vulnerability scanning, and evidence collection.

## Features

### Reconnaissance & Enumeration
- **Port Scanning**: Fast TCP connect probe with CIDR support and concurrent scanning
- **Service Detection**: Banner grabbing, version fingerprinting, and service identification
- **DNS Enumeration**:
  - Subdomain discovery via brute-force (~200 common prefixes)
  - Certificate Transparency logs lookup (crt.sh integration)
  - Zone transfer attempts
  - Reverse DNS lookup
  - CNAME record detection
- **HTTP Analysis**: Technology fingerprinting, security header analysis, directory brute-force
- **SSL/TLS Analysis**: Certificate inspection, cipher enumeration, vulnerability detection (POODLE, BEAST, etc.)
- **SMB/NetBIOS**: Share enumeration, null session testing, EternalBlue detection
- **SNMP Enumeration**: Community string brute-force, system information gathering

### Vulnerability Scanning
- **Nuclei Integration**: Wrapper for ProjectDiscovery's Nuclei scanner with template management
- **Authentication Testing**: Brute-force attacks, password spraying, default credential checking

### Workflow & Automation
- **Workflow Engine**: YAML-based workflow definitions with dependency management
- **Predefined Workflows**: Quick-recon, web-assessment, full-assessment
- **Parallel Execution**: Run independent modules concurrently

### Reporting
- **Multiple Formats**: JSON, Markdown, HTML export
- **Professional Reports**:
  - Executive summary with findings by severity
  - Clickable statistics (jump to severity sections in HTML)
  - SSL/TLS certificate inventory table
  - Network topology diagram (SVG embedded in HTML)
  - Evidence collection and screenshots
- **Workspace Organization**: Structured artifact storage per engagement

### User Interface
- **CLI**: Full-featured command-line interface with Cobra
- **TUI**: Interactive terminal UI with Bubble Tea
  - DNS-first workflow: Enter domain → DNS enumeration → Select targets → Run scans
  - Real-time progress display
  - Target selection with checkboxes

---

## Installation

### Prerequisites
- Go 1.22+
- GNU Make (optional, for convenience)
- [Nuclei](https://github.com/projectdiscovery/nuclei) (optional, for vulnerability scanning)

### Build from source

```bash
git clone https://github.com/tldr-it-stepankutaj/pentakit.git
cd pentakit
make build
```

The compiled binary will be available at `./bin/pentakit`.

### Download Release

Download pre-built binaries from the [Releases](https://github.com/tldr-it-stepankutaj/pentakit/releases) page.

---

## Quick Start

### Initialize a workspace

```bash
./bin/pentakit --workspace ./work init
```

This creates a directory structure:

```
work/
├── artifacts/
│   ├── http/
│   ├── pcap/
│   └── screenshots/
├── cache/
├── findings/
├── logs/
└── reports/
```

### Run TUI mode (Recommended)

```bash
./bin/pentakit --workspace ./work --tui
```

The TUI provides a guided workflow:
1. Enter target domain
2. DNS enumeration discovers subdomains (via brute-force + CT logs)
3. Select targets from discovered hosts
4. Run HTTP/SSL/Service analysis on selected targets
5. Generate comprehensive report

---

## CLI Commands

### Port Scanning (recon)

```bash
# Scan common ports
./bin/pentakit recon --target 192.168.1.10

# Scan specific ports
./bin/pentakit recon --target 192.168.1.0/24 --ports 22,80,443,8080

# Scan port range
./bin/pentakit recon --target example.com --ports 1-1000
```

### Service Detection

```bash
# Detect services with banner grabbing
./bin/pentakit services --target 192.168.1.10 --ports 22,80,443
```

### DNS Enumeration

```bash
# Basic DNS lookup
./bin/pentakit dns --domain example.com

# Subdomain brute-force
./bin/pentakit dns --domain example.com --bruteforce

# Certificate Transparency logs lookup (finds all subdomains from SSL certs)
./bin/pentakit dns --domain example.com --ct-logs

# Zone transfer attempt
./bin/pentakit dns --domain example.com --zone-transfer

# Reverse DNS lookup
./bin/pentakit dns --range 192.168.1.0/24 --reverse

# Full enumeration (all methods)
./bin/pentakit dns --domain example.com --bruteforce --ct-logs --zone-transfer
```

### HTTP Analysis

```bash
# Technology fingerprinting and header analysis
./bin/pentakit http --target https://example.com

# Directory brute-force
./bin/pentakit http --target https://example.com --dir-bruteforce

# With custom wordlist and extensions
./bin/pentakit http --target https://example.com --dir-bruteforce --wordlist /path/to/wordlist.txt --ext php,html,js
```

### SSL/TLS Analysis

```bash
# Basic SSL analysis
./bin/pentakit ssl --target example.com

# Full analysis (all versions and ciphers)
./bin/pentakit ssl --target example.com --port 443 --all
```

### Nuclei Vulnerability Scanning

```bash
# Quick CVE scan
./bin/pentakit nuclei --target https://example.com --tags cve --severity high,critical

# Full web scan
./bin/pentakit nuclei --target https://example.com --tags cve,exposure,misconfiguration

# Multiple targets
./bin/pentakit nuclei --target https://example.com --target https://test.com
```

### Report Generation

```bash
# Generate Markdown report
./bin/pentakit report

# Generate HTML report with network diagram
./bin/pentakit report --format html --diagram

# Generate JSON report
./bin/pentakit report --format json

# Custom title
./bin/pentakit report --format html --diagram --title "Security Assessment - Example Corp"
```

The HTML report includes:
- Clickable severity statistics (jump to Critical/High/Medium/Low/Info sections)
- Network topology SVG diagram
- SSL certificate inventory table
- Color-coded findings by severity

### Authentication Testing

```bash
# HTTP basic auth brute-force
./bin/pentakit bruteforce --target example.com --protocol http --users users.txt --passwords passwords.txt

# Password spraying
./bin/pentakit bruteforce --target example.com --protocol http --users users.txt --password "Summer2024!" --spray

# Single credential test
./bin/pentakit bruteforce --target example.com --protocol ftp --user admin --password admin
```

### SMB Enumeration

```bash
# Full SMB enumeration
./bin/pentakit smb --target 192.168.1.10

# Share enumeration with null session
./bin/pentakit smb --target 192.168.1.10 --null-session --shares
```

### SNMP Enumeration

```bash
# Community string brute-force
./bin/pentakit snmp --target 192.168.1.10

# With specific community string
./bin/pentakit snmp --target 192.168.1.10 --community public --walk
```

### Workflows

```bash
# List available workflows
./bin/pentakit workflow list

# Run quick reconnaissance workflow
./bin/pentakit workflow run --name quick-recon --target 192.168.1.10

# Run web assessment workflow
./bin/pentakit workflow run --name web-assessment --target https://example.com

# Run custom workflow from YAML file
./bin/pentakit workflow run --file my-workflow.yaml --target 192.168.1.10
```

---

## Workflow Definition (YAML)

Create custom workflows in YAML:

```yaml
name: Custom Assessment
description: Custom penetration test workflow
variables:
  default_ports: "21,22,80,443,3306,8080"

steps:
  - id: recon
    name: Port Scan
    module: recon
    config:
      ports: [21, 22, 80, 443, 8080]

  - id: services
    name: Service Detection
    module: services
    depends_on: [recon]
    config:
      grab_banner: true

  - id: http
    name: HTTP Analysis
    module: http
    depends_on: [services]
    condition: "services.found_count > 0"
    config:
      tech_fingerprint: true
      header_analysis: true

  - id: nuclei
    name: Vulnerability Scan
    module: nuclei
    depends_on: [http]
    config:
      template_tags: [cve, misconfiguration]
      severity: [medium, high, critical]
```

---

## Project Structure

```
cmd/
  main/               # Main entrypoint
  pentakit/           # CLI commands
internal/
  app/                # App context and configuration
  modules/            # Pluggable modules
    recon/            # Port scanning
    services/         # Service detection
    dns/              # DNS enumeration (brute-force, CT logs, zone transfer)
    http/             # HTTP analysis
    ssl/              # SSL/TLS analysis
    nuclei/           # Nuclei integration
    bruteforce/       # Authentication testing
    smb/              # SMB enumeration
    snmp/             # SNMP enumeration
  reports/            # Report generation (JSON, MD, HTML, network diagrams)
  tui/                # Bubble Tea TUI
  workflow/           # Workflow engine
  workspace/          # Workspace management
pkg/version/          # Version info
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PENTAKIT_WORKSPACE` | Workspace directory path | `./work` |
| `PENTAKIT_TIMEOUT` | Default operation timeout | `30s` |
| `PENTAKIT_LOG_LEVEL` | Log level (debug/info/warn/error) | `info` |

---

## Development

### Run directly

```bash
go run ./cmd/main --workspace ./work --tui
```

### Run tests

```bash
make test
```

### Build

```bash
make build
```

### Build for specific platform

```bash
# macOS ARM64
GOOS=darwin GOARCH=arm64 go build -o ./bin/pentakit-darwin-arm64 ./cmd/main

# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o ./bin/pentakit-linux-amd64 ./cmd/main

# Windows AMD64
GOOS=windows GOARCH=amd64 go build -o ./bin/pentakit-windows-amd64.exe ./cmd/main
```

### Tidy modules

```bash
make tidy
```

---

## Security Considerations

This tool is designed for **authorized penetration testing** and security assessments only. Always ensure you have proper authorization before testing any systems.

- Never use against systems without explicit permission
- Respect rate limits and avoid denial of service
- Handle discovered credentials and vulnerabilities responsibly
- Follow responsible disclosure practices

---

## Contributing

Contributions are welcome. Please:
- Keep all code comments in **English**
- Follow the existing project structure (new modules go to `internal/modules/`)
- Write small, composable packages that can be tested in isolation
- Add tests for new functionality

---

## License

MIT License. See [LICENSE](LICENSE) for details.
