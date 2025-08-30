# pentakit

Extensible Go-based pentest toolkit with optional TUI (`--tui`).

## Quick start
```bash
make build
./bin/pentakit --workspace ./work init
./bin/pentakit --workspace ./work recon --target 192.168.1.10
./bin/pentakit --workspace ./work --tui