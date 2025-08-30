package workspace

import (
	"fmt"
	"os"
	"path/filepath"
)

// Handle implements app.WorkspaceHandle and provides helper methods.
type Handle struct {
	Root string
}

// Path joins workspace root with provided parts.
func (h Handle) Path(parts ...string) string {
	all := append([]string{h.Root}, parts...)
	return filepath.Join(all...)
}

// Ensure creates the workspace directory structure if missing.
func Ensure(root string) (Handle, error) {
	h := Handle{Root: root}
	// Standard directories; extend freely as the project grows.
	dirs := []string{
		root,
		filepath.Join(root, "artifacts"),
		filepath.Join(root, "artifacts", "screenshots"),
		filepath.Join(root, "artifacts", "http"),
		filepath.Join(root, "artifacts", "pcap"),
		filepath.Join(root, "findings"),
		filepath.Join(root, "logs"),
		filepath.Join(root, "reports"),
		// Module-specific caches
		filepath.Join(root, "cache"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return h, fmt.Errorf("failed to create directory %s: %w", d, err)
		}
	}
	return h, nil
}
