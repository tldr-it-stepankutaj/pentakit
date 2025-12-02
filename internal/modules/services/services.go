package services

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tldr-it-stepankutaj/pentakit/internal/app"
)

// Module implements the service detection module metadata.
type Module struct{}

func New() Module { return Module{} }

func (Module) Name() string        { return "services" }
func (Module) Description() string { return "Service detection via banner grabbing and fingerprinting" }

// RunConfig configures the service detection run.
type RunConfig struct {
	Target        string
	Ports         []int
	Timeout       time.Duration
	Concurrency   int
	GrabBanner    bool
	DetectVersion bool
}

// Result represents a detected service.
type Result struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	Service    string `json:"service"`
	Version    string `json:"version,omitempty"`
	Banner     string `json:"banner,omitempty"`
	Confidence int    `json:"confidence"` // 0-100
}

// ServiceSignature represents a pattern for identifying services.
type ServiceSignature struct {
	Name    string
	Pattern *regexp.Regexp
	Version *regexp.Regexp // optional: extracts version from banner
}

// Common service signatures for fingerprinting.
var signatures = []ServiceSignature{
	{Name: "SSH", Pattern: regexp.MustCompile(`^SSH-`), Version: regexp.MustCompile(`SSH-[\d.]+-(\S+)`)},
	{Name: "HTTP", Pattern: regexp.MustCompile(`^HTTP/|^<!DOCTYPE|^<html`), Version: regexp.MustCompile(`Server:\s*(\S+)`)},
	{Name: "FTP", Pattern: regexp.MustCompile(`^220[- ]`), Version: regexp.MustCompile(`220[- ].*?(\S+\s+FTP|\S+ftpd)`)},
	{Name: "SMTP", Pattern: regexp.MustCompile(`^220[- ].*SMTP|^220[- ].*mail`), Version: regexp.MustCompile(`220[- ](\S+)`)},
	{Name: "POP3", Pattern: regexp.MustCompile(`^\+OK`), Version: regexp.MustCompile(`\+OK\s+(\S+)`)},
	{Name: "IMAP", Pattern: regexp.MustCompile(`^\* OK.*IMAP`), Version: regexp.MustCompile(`IMAP[^\s]*\s+(\S+)`)},
	{Name: "MySQL", Pattern: regexp.MustCompile(`mysql|MariaDB`), Version: regexp.MustCompile(`([\d.]+)-MariaDB|([\d.]+)-mysql`)},
	{Name: "PostgreSQL", Pattern: regexp.MustCompile(`PostgreSQL|PGSQL`), Version: regexp.MustCompile(`PostgreSQL\s+([\d.]+)`)},
	{Name: "Redis", Pattern: regexp.MustCompile(`-ERR.*redis|REDIS`), Version: regexp.MustCompile(`redis_version:([\d.]+)`)},
	{Name: "MongoDB", Pattern: regexp.MustCompile(`MongoDB|ismaster`), Version: nil},
	{Name: "Memcached", Pattern: regexp.MustCompile(`^ERROR\r?\n|STAT pid`), Version: regexp.MustCompile(`STAT version ([\d.]+)`)},
	{Name: "RDP", Pattern: regexp.MustCompile(`^\x03\x00`), Version: nil},
	{Name: "VNC", Pattern: regexp.MustCompile(`^RFB `), Version: regexp.MustCompile(`RFB ([\d.]+)`)},
	{Name: "Telnet", Pattern: regexp.MustCompile(`^\xff[\xfb\xfd\xfe]|login:|Login:`), Version: nil},
	{Name: "DNS", Pattern: regexp.MustCompile(`^\x00.*\x00\x01\x00`), Version: nil},
	{Name: "LDAP", Pattern: regexp.MustCompile(`^\x30`), Version: nil},
	{Name: "SMB", Pattern: regexp.MustCompile(`^\x00\x00\x00.*SMB`), Version: nil},
	{Name: "Elasticsearch", Pattern: regexp.MustCompile(`"cluster_name"|elasticsearch`), Version: regexp.MustCompile(`"number"\s*:\s*"([\d.]+)"`)},
	{Name: "Docker", Pattern: regexp.MustCompile(`Docker|docker`), Version: regexp.MustCompile(`Docker/([\d.]+)`)},
	{Name: "Kubernetes", Pattern: regexp.MustCompile(`kubernetes|k8s`), Version: nil},
}

// PortServiceHint maps common ports to likely services.
var portServiceHint = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	111:   "RPC",
	135:   "MSRPC",
	139:   "NetBIOS",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	465:   "SMTPS",
	587:   "SMTP",
	993:   "IMAPS",
	995:   "POP3S",
	1433:  "MSSQL",
	1521:  "Oracle",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	6379:  "Redis",
	8080:  "HTTP-Proxy",
	8443:  "HTTPS-Alt",
	9200:  "Elasticsearch",
	27017: "MongoDB",
	11211: "Memcached",
}

// Run executes service detection on the target.
func Run(ctx app.Context, cfg RunConfig) ([]Result, error) {
	if cfg.Target == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}
	if len(cfg.Ports) == 0 {
		return nil, fmt.Errorf("no ports specified")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 50
	}

	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make([]Result, 0)

	for _, port := range cfg.Ports {
		port := port
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()

			result := detectService(ctx.Ctx, cfg.Target, port, cfg.Timeout, cfg.GrabBanner)
			if result != nil {
				mu.Lock()
				results = append(results, *result)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Sort results by port
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	// Print results
	for _, r := range results {
		if r.Version != "" {
			fmt.Printf("%s:%d %s %s (%s)\n", r.Host, r.Port, r.Service, r.Version, r.Banner)
		} else if r.Banner != "" {
			fmt.Printf("%s:%d %s (%s)\n", r.Host, r.Port, r.Service, truncate(r.Banner, 60))
		} else {
			fmt.Printf("%s:%d %s\n", r.Host, r.Port, r.Service)
		}
	}

	// Persist results
	timestamp := ctx.Now.Format("20060102-150405")
	jsonlPath := ctx.Workspace.Path("findings", fmt.Sprintf("services-%s.jsonl", timestamp))
	if err := writeJSONL(jsonlPath, results); err != nil {
		fmt.Printf("[!] failed to write findings: %v\n", err)
	}

	return results, nil
}

func detectService(ctx context.Context, host string, port int, timeout time.Duration, grabBanner bool) *Result {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: timeout}

	connCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialer.DialContext(connCtx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

	result := &Result{
		Host:       host,
		Port:       port,
		Protocol:   "tcp",
		Service:    "unknown",
		Confidence: 0,
	}

	// First, try port-based hint
	if hint, ok := portServiceHint[port]; ok {
		result.Service = hint
		result.Confidence = 30
	}

	if !grabBanner {
		return result
	}

	// Try to grab banner
	banner := grabBannerFromConn(conn, timeout)
	if banner != "" {
		result.Banner = banner

		// Try to match against signatures
		for _, sig := range signatures {
			if sig.Pattern.MatchString(banner) {
				result.Service = sig.Name
				result.Confidence = 80

				if sig.Version != nil {
					if matches := sig.Version.FindStringSubmatch(banner); len(matches) > 1 {
						for _, m := range matches[1:] {
							if m != "" {
								result.Version = m
								result.Confidence = 95
								break
							}
						}
					}
				}
				break
			}
		}
	}

	// Send probes for services that don't send banner first
	if result.Confidence < 50 {
		probedBanner := sendProbes(conn, timeout)
		if probedBanner != "" && probedBanner != banner {
			result.Banner = probedBanner
			for _, sig := range signatures {
				if sig.Pattern.MatchString(probedBanner) {
					result.Service = sig.Name
					result.Confidence = 75
					if sig.Version != nil {
						if matches := sig.Version.FindStringSubmatch(probedBanner); len(matches) > 1 {
							for _, m := range matches[1:] {
								if m != "" {
									result.Version = m
									result.Confidence = 90
									break
								}
							}
						}
					}
					break
				}
			}
		}
	}

	return result
}

func grabBannerFromConn(conn net.Conn, timeout time.Duration) string {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return ""
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	return sanitizeBanner(string(buf[:n]))
}

func sendProbes(conn net.Conn, timeout time.Duration) string {
	probes := [][]byte{
		[]byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
		[]byte("HELP\r\n"),
		[]byte("\r\n"),
	}

	for _, probe := range probes {
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			continue
		}
		_, err := conn.Write(probe)
		if err != nil {
			continue
		}

		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			continue
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			return sanitizeBanner(string(buf[:n]))
		}
	}
	return ""
}

func sanitizeBanner(s string) string {
	// Remove null bytes and control characters except newlines/tabs
	var result strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r < 127) {
			result.WriteRune(r)
		}
	}
	return strings.TrimSpace(result.String())
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func writeJSONL(path string, results []Result) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// Use append mode so multiple calls don't overwrite
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
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
