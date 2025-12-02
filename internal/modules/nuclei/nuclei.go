package nuclei

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tldr-it-stepankutaj/pentakit/internal/app"
)

// Module implements the Nuclei integration module metadata.
type Module struct{}

func New() Module { return Module{} }

func (Module) Name() string        { return "nuclei" }
func (Module) Description() string { return "Nuclei vulnerability scanner integration" }

// RunConfig configures the Nuclei scan.
type RunConfig struct {
	Targets         []string // Target URLs or hosts
	TargetFile      string   // File containing targets
	Templates       []string // Specific templates to run
	TemplateTags    []string // Template tags to filter (e.g., cve, rce, sqli)
	ExcludeTags     []string // Tags to exclude
	Severity        []string // Filter by severity (info, low, medium, high, critical)
	Timeout         time.Duration
	RateLimit       int    // Requests per second
	BulkSize        int    // Number of targets to process in parallel
	Concurrency     int    // Number of templates to run in parallel
	Headless        bool   // Enable headless browser-based templates
	NewTemplates    bool   // Run only new templates
	AutomaticScan   bool   // Run automatic web scan
	OutputFormat    string // json, jsonl, or text
	CustomHeaders   map[string]string
	ProxyURL        string
	FollowRedirects bool
	MaxRedirects    int
	Retries         int
}

// Result represents a Nuclei finding.
type Result struct {
	Template         string       `json:"template"`
	TemplateID       string       `json:"template-id"`
	TemplatePath     string       `json:"template-path,omitempty"`
	Info             TemplateInfo `json:"info"`
	Type             string       `json:"type"`
	Host             string       `json:"host"`
	Matched          string       `json:"matched-at"`
	ExtractedResults []string     `json:"extracted-results,omitempty"`
	Request          string       `json:"request,omitempty"`
	Response         string       `json:"response,omitempty"`
	IP               string       `json:"ip,omitempty"`
	Timestamp        time.Time    `json:"timestamp"`
	CURLCommand      string       `json:"curl-command,omitempty"`
	MatcherStatus    bool         `json:"matcher-status"`
	MatchedLine      string       `json:"matched-line,omitempty"`
}

// TemplateInfo contains template metadata.
type TemplateInfo struct {
	Name           string         `json:"name"`
	Author         string         `json:"author"`
	Tags           []string       `json:"tags,omitempty"`
	Description    string         `json:"description,omitempty"`
	Reference      []string       `json:"reference,omitempty"`
	Severity       string         `json:"severity"`
	Classification Classification `json:"classification,omitempty"`
}

// Classification contains CVE/CWE information.
type Classification struct {
	CVEId       []string `json:"cve-id,omitempty"`
	CWEId       []string `json:"cwe-id,omitempty"`
	CVSSMetrics string   `json:"cvss-metrics,omitempty"`
	CVSSScore   float64  `json:"cvss-score,omitempty"`
}

// Predefined template tag sets for common use cases.
var TemplateSets = map[string][]string{
	"quick":       {"cve", "default-login", "misconfiguration"},
	"web":         {"cve", "exposure", "misconfiguration", "xss", "sqli", "lfi", "rce"},
	"network":     {"network", "dns", "ssl"},
	"cves":        {"cve"},
	"misconfig":   {"misconfiguration", "exposure", "default-login"},
	"takeover":    {"takeover"},
	"tech-detect": {"tech"},
	"full":        {}, // Empty means all templates
}

// Run executes Nuclei scan.
func Run(ctx app.Context, cfg RunConfig) ([]Result, error) {
	// Check if nuclei is installed
	nucleiPath, err := exec.LookPath("nuclei")
	if err != nil {
		return nil, fmt.Errorf("nuclei not found in PATH. Install it from: https://github.com/projectdiscovery/nuclei")
	}

	if len(cfg.Targets) == 0 && cfg.TargetFile == "" {
		return nil, fmt.Errorf("at least one target or target file is required")
	}

	// Build nuclei command
	args := buildNucleiArgs(ctx, cfg)

	fmt.Printf("[*] Running Nuclei scan...\n")
	fmt.Printf("[*] Command: nuclei %s\n", strings.Join(args, " "))

	// Create output file for JSON results
	timestamp := ctx.Now.Format("20060102-150405")
	outputFile := ctx.Workspace.Path("findings", fmt.Sprintf("nuclei-%s.jsonl", timestamp))

	// Add output arguments
	args = append(args, "-jsonl", "-o", outputFile)

	// Execute nuclei - let it manage its own timeouts
	cmd := exec.Command(nucleiPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// Don't fail on non-zero exit - nuclei returns non-zero when vulnerabilities are found
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit code 1 = vulnerabilities found (success)
			// Exit code 0 = no vulnerabilities found (success)
			// Other codes = actual errors
			if exitErr.ExitCode() > 1 {
				return nil, fmt.Errorf("nuclei failed with exit code %d: %w", exitErr.ExitCode(), err)
			}
		} else {
			return nil, fmt.Errorf("nuclei failed: %w", err)
		}
	}

	// Parse results
	results, err := parseResults(outputFile)
	if err != nil {
		fmt.Printf("[!] Warning: could not parse results: %v\n", err)
		return nil, nil
	}

	// Print summary
	printSummary(results)

	return results, nil
}

func buildNucleiArgs(ctx app.Context, cfg RunConfig) []string {
	var args []string

	// Targets
	for _, t := range cfg.Targets {
		args = append(args, "-u", t)
	}
	if cfg.TargetFile != "" {
		args = append(args, "-l", cfg.TargetFile)
	}

	// Templates
	for _, t := range cfg.Templates {
		args = append(args, "-t", t)
	}

	// Template tags
	if len(cfg.TemplateTags) > 0 {
		args = append(args, "-tags", strings.Join(cfg.TemplateTags, ","))
	}

	// Exclude tags
	if len(cfg.ExcludeTags) > 0 {
		args = append(args, "-exclude-tags", strings.Join(cfg.ExcludeTags, ","))
	}

	// Severity filter
	if len(cfg.Severity) > 0 {
		args = append(args, "-severity", strings.Join(cfg.Severity, ","))
	}

	// Rate limiting
	if cfg.RateLimit > 0 {
		args = append(args, "-rate-limit", fmt.Sprintf("%d", cfg.RateLimit))
	}

	// Concurrency
	if cfg.BulkSize > 0 {
		args = append(args, "-bulk-size", fmt.Sprintf("%d", cfg.BulkSize))
	}
	if cfg.Concurrency > 0 {
		args = append(args, "-concurrency", fmt.Sprintf("%d", cfg.Concurrency))
	}

	// Headless
	if cfg.Headless {
		args = append(args, "-headless")
	}

	// New templates only
	if cfg.NewTemplates {
		args = append(args, "-new-templates")
	}

	// Automatic scan
	if cfg.AutomaticScan {
		args = append(args, "-automatic-scan")
	}

	// Custom headers
	for k, v := range cfg.CustomHeaders {
		args = append(args, "-header", fmt.Sprintf("%s: %s", k, v))
	}

	// Proxy
	if cfg.ProxyURL != "" {
		args = append(args, "-proxy", cfg.ProxyURL)
	}

	// Redirects
	if cfg.FollowRedirects {
		args = append(args, "-follow-redirects")
		if cfg.MaxRedirects > 0 {
			args = append(args, "-max-redirects", fmt.Sprintf("%d", cfg.MaxRedirects))
		}
	}

	// Retries
	if cfg.Retries > 0 {
		args = append(args, "-retries", fmt.Sprintf("%d", cfg.Retries))
	}

	// Per-request timeout (use 10 seconds default)
	args = append(args, "-timeout", "10")

	// Stats for progress
	args = append(args, "-stats")

	return args
}

func parseResults(filePath string) ([]Result, error) {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No results file means no findings
		}
		return nil, err
	}
	defer file.Close()

	var results []Result
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024) // 10MB max line size

	for scanner.Scan() {
		var result Result
		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
			continue // Skip malformed lines
		}
		results = append(results, result)
	}

	return results, scanner.Err()
}

func printSummary(results []Result) {
	if len(results) == 0 {
		fmt.Println("\n[*] No vulnerabilities found")
		return
	}

	// Count by severity
	severityCounts := make(map[string]int)
	templateCounts := make(map[string]int)

	for _, r := range results {
		severity := strings.ToLower(r.Info.Severity)
		if severity == "" {
			severity = "unknown"
		}
		severityCounts[severity]++
		templateCounts[r.TemplateID]++
	}

	fmt.Printf("\n[+] Found %d vulnerabilities:\n", len(results))

	// Print severity breakdown
	severityOrder := []string{"critical", "high", "medium", "low", "info", "unknown"}
	for _, sev := range severityOrder {
		if count, ok := severityCounts[sev]; ok {
			fmt.Printf("    %s: %d\n", strings.ToUpper(sev), count)
		}
	}

	// Print unique findings
	fmt.Printf("\n[*] Unique findings:\n")
	for _, r := range results {
		severity := strings.ToUpper(r.Info.Severity)
		if severity == "" {
			severity = "INFO"
		}
		fmt.Printf("    [%s] %s - %s\n", severity, r.Info.Name, r.Host)

		// Print CVE if available
		if len(r.Info.Classification.CVEId) > 0 {
			fmt.Printf("           CVE: %s\n", strings.Join(r.Info.Classification.CVEId, ", "))
		}
	}
}

// QuickScan runs a quick vulnerability scan with common templates.
func QuickScan(ctx app.Context, targets []string) ([]Result, error) {
	cfg := RunConfig{
		Targets:      targets,
		TemplateTags: TemplateSets["quick"],
		Severity:     []string{"medium", "high", "critical"},
		Timeout:      30 * time.Minute,
		RateLimit:    150,
		Concurrency:  25,
	}
	return Run(ctx, cfg)
}

// WebScan runs a comprehensive web application scan.
func WebScan(ctx app.Context, targets []string) ([]Result, error) {
	cfg := RunConfig{
		Targets:         targets,
		TemplateTags:    TemplateSets["web"],
		Timeout:         60 * time.Minute,
		RateLimit:       100,
		Concurrency:     25,
		FollowRedirects: true,
		MaxRedirects:    5,
	}
	return Run(ctx, cfg)
}

// CVEScan runs a scan focused on known CVEs.
func CVEScan(ctx app.Context, targets []string, severities []string) ([]Result, error) {
	if len(severities) == 0 {
		severities = []string{"medium", "high", "critical"}
	}
	cfg := RunConfig{
		Targets:      targets,
		TemplateTags: []string{"cve"},
		Severity:     severities,
		Timeout:      45 * time.Minute,
		RateLimit:    100,
		Concurrency:  25,
	}
	return Run(ctx, cfg)
}

// TechDetect runs technology detection scan.
func TechDetect(ctx app.Context, targets []string) ([]Result, error) {
	cfg := RunConfig{
		Targets:      targets,
		TemplateTags: []string{"tech"},
		Timeout:      15 * time.Minute,
		RateLimit:    200,
		Concurrency:  50,
	}
	return Run(ctx, cfg)
}

// UpdateTemplates updates Nuclei templates to the latest version.
func UpdateTemplates() error {
	fmt.Println("[*] Updating Nuclei templates...")
	cmd := exec.Command("nuclei", "-update-templates")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ListTemplates lists available templates matching criteria.
func ListTemplates(tags []string, severity []string) error {
	args := []string{"-tl"}

	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	if len(severity) > 0 {
		args = append(args, "-severity", strings.Join(severity, ","))
	}

	cmd := exec.Command("nuclei", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// WriteTargetsFile writes targets to a file for bulk scanning.
func WriteTargetsFile(path string, targets []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, t := range targets {
		fmt.Fprintln(w, t)
	}
	return w.Flush()
}
