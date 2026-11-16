// Package fsutil holds small file-I/O helpers shared by every scan module.
//
// Before this package existed, loadWordlist/writeJSONL/writeJSON/truncate
// were each copy-pasted into 2-5 module packages independently. That had
// already drifted: bruteforce's loadWordlist didn't trim whitespace or skip
// "#comment" lines the way dns/http/snmp's (identical to each other) did, so
// the exact same wordlist file behaved differently depending on which
// command read it, and http's truncate left \n/\r in truncated text while
// services' otherwise-identical truncate stripped them first. Consolidating
// to one implementation each removes the duplication and the drift in the
// same step.
package fsutil

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// LoadWordlist reads one entry per line from path. Blank lines and lines
// starting with "#" (after trimming surrounding whitespace) are skipped.
func LoadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var words []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}
	return words, scanner.Err()
}

// WriteJSONL writes one JSON object per line to path, creating parent
// directories as needed. Every call site passes a freshly timestamped
// filename, so this always creates/truncates rather than appends — a couple
// of the original copies opened in append mode for no actual effect, since
// nothing ever wrote to the same path twice within one run.
func WriteJSONL[T any](path string, results []T) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, r := range results {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return w.Flush()
}

// WriteJSON writes a single indented JSON object to path, creating parent
// directories as needed.
func WriteJSON[T any](path string, result T) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return err
	}
	return w.Flush()
}

// Truncate shortens s to at most maxLen runes of visible text, appending
// "..." when it had to cut. Newlines/carriage returns are flattened to
// spaces first so a banner or page title containing them can never break a
// single-line console report into extra lines.
func Truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
