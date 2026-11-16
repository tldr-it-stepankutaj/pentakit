# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.1] - 2026-11-16

### Fixed
- **Workflow engine was completely non-functional**: no module was ever registered with `workflow.RegisterModule`, so every predefined workflow (`quick-recon`, `web-assessment`, `full-assessment`) and every custom YAML workflow failed with "unknown module". All 9 modules are now wired up at startup.
- `.gitignore` had an unanchored `pentakit` pattern that silently excluded the entire `cmd/pentakit/` source directory from git.
- `bruteforce`'s `StopOnSuccess` path had a race condition that could double-close a channel and panic; fixed with `sync.Once`.
- `services` detection took up to the full operation timeout (default 30s) per silent port (e.g. PostgreSQL, which never sends an unprompted banner) because the banner read and three sequential probe reads all reused the same long timeout. A scan of one silent port now completes in a few seconds instead of up to 30s.
- Removed a corrupted/invalid SNMP community string left in `snmp.go`.
- TUI: every scan action ran synchronously inside Bubble Tea's `Update()`, blocking the entire UI (no redraw, no spinner, no way to cancel) for the whole scan duration. Scans now run as background commands with a live spinner, and `q`/`Ctrl+C`/`Esc` work while a scan is in progress.
- TUI: the discovered-target list order was nondeterministic (built from a Go map) and could reshuffle between identical runs over the same DNS data. The list is now sorted by domain.
- TUI: scan results reported only a bare success count with no indication of failures; results now report `succeeded/attempted` or `scanned/failed` counts.

### Added
- Real SSH credential verification in `bruteforce` (`golang.org/x/crypto/ssh`), replacing a placeholder that always returned false.
- `pentakit modules list` (and `modules list --json`) to introspect the registered module registry.
- Workflow step output chaining: a dependent step's `ports` config can reference `${<step>.output}` to use the previous step's discovered results (e.g. `recon` → `services`) instead of a hardcoded port list.
- New `internal/fsutil` package consolidating wordlist loading and JSON/JSONL writing that was duplicated across `bruteforce`, `dns`, `http`, `snmp`, `recon`, `services`, and `ssl` — this also fixed a behavioral inconsistency where `bruteforce`'s wordlist loader, unlike the others, didn't trim whitespace or skip comment lines.
- New `internal/targets` package consolidating target/CIDR expansion previously duplicated between `recon` and `dns`.
- Test coverage for the workflow engine, module registration/config helpers, SSH bruteforce (against an in-process test server), and the `services` banner-timeout fix.

### Changed
- `recon.Run` now returns discovered results (`([]Result, error)`) instead of only an error, enabling the workflow output-chaining feature above.
- Updated GitHub Actions to current major versions (`checkout`, `setup-go`, `upload-artifact`, `download-artifact`, `codecov-action`, `golangci-lint-action`, `action-gh-release`) in `ci.yml` and `release.yml`.
- Added CI/release/Go-version/license badges and expanded documentation in `README.md`.

## [1.0.0] - 2025-12-02

Initial release.

### Added
- CLI and interactive TUI (`--tui`) built on Cobra and Bubble Tea.
- Reconnaissance modules: port scanning (`recon`), service/banner detection (`services`), DNS enumeration with brute-force/CT-logs/zone-transfer (`dns`), HTTP analysis (`http`), SSL/TLS analysis (`ssl`), SMB enumeration (`smb`), SNMP enumeration (`snmp`).
- Vulnerability scanning via Nuclei integration.
- Authentication testing module (`bruteforce`) with brute-force and password-spraying support.
- YAML-based workflow engine with predefined workflows (`quick-recon`, `web-assessment`, `full-assessment`).
- Report generation in JSON, Markdown, and HTML (with network topology diagrams and SSL certificate inventory).
- Workspace management for structured per-engagement artifact storage.
