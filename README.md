# Pentakit

Pentakit is an extensible **Go-based penetration testing toolkit**.  
It provides a modular CLI and an optional TUI (`--tui`) to automate repeatable pentest workflows such as reconnaissance, enumeration, and evidence collection.

## Features (MVP)

- **Workspaces**: keep all artifacts, logs, findings, and reports organized per engagement.
- **Reconnaissance module**: fast TCP connect probe with configurable target and ports.
- **TUI (Text User Interface)**: minimal Bubble Tea interface (`--tui` flag) for interactive runs.
- **Extensible architecture**: new modules can be added under `internal/modules/`.

Planned features:
- HTTP enumeration, screenshots, and technology fingerprinting.
- Integration with third-party tools (e.g., `nuclei`, `amass`, `gobuster`).
- Evidence storage and Markdown → PDF reporting.

---

## Installation

### Prerequisites
- Go 1.22+  
- GNU Make (optional, for convenience)

### Build from source

```bash
git clone https://github.com/tldr-it-stepankutaj/pentakit.git
cd pentakit
make build
```

The compiled binary will be available at `./bin/pentakit`.

---

## Usage

Run the binary with `--help` to see available commands:

```bash
./bin/pentakit --help
```

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

### Run reconnaissance

```bash
./bin/pentakit --workspace ./work recon --target 192.168.1.10
```

By default, it probes a set of common ports (`80, 443, 8080, 8443, 22, 3389, 5432, 3306`).

Output example:

```
192.168.1.10:22 open
192.168.1.10:80 open
192.168.1.10:443 open
```

### Run in TUI mode

```bash
./bin/pentakit --workspace ./work --tui
```

- Press **r** to run recon with the default target (currently empty placeholder).
- Press **q** to quit.

---

## Project structure

```
cmd/pentakit/         # main entrypoint (main.go)
internal/
  cli/                # Cobra root + commands
  app/                # app context and config
  workspace/          # workspace management
  modules/            # pluggable modules (recon, http, etc.)
  tui/                # Bubble Tea TUI implementation
pkg/version/          # version info
templates/            # report templates (Markdown)
```

---

## Development

### Run directly

```bash
go run ./cmd/pentakit --workspace ./work recon --target 127.0.0.1
```

### Run tests

```bash
make test
```

### Tidy modules

```bash
make tidy
```

---

## Contributing

Contributions are welcome. Please:
- Keep all code comments in **English**.
- Follow the existing project structure (new modules go to `internal/modules/`).
- Write small, composable packages that can be tested in isolation.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
