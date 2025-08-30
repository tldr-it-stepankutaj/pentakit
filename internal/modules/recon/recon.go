package recon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"text/template"
	"time"

	"github.com/tldr-it-stepankutaj/pentakit/internal/app"
)

// Module implements the basic recon module metadata.
type Module struct{}

func New() Module { return Module{} }

func (Module) Name() string        { return "recon" }
func (Module) Description() string { return "Basic TCP connect probe for a target or CIDR range" }

// RunConfig configures the recon run.
type RunConfig struct {
	Target          string        // single host/hostname or CIDR (e.g., 192.168.1.0/24)
	Ports           []int         // ports to probe
	Timeout         time.Duration // per-connection timeout
	PortConcurrency int           // concurrent dials per host
	HostConcurrency int           // concurrent hosts in a range
}

// Result represents a single open port finding.
type Result struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// expandTarget expands a single target or a CIDR range into a list of IPs.
func expandTarget(target string) ([]string, error) {
	// Try to parse as CIDR
	if ip, ipnet, err := net.ParseCIDR(target); err == nil {
		var ips []string
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); ip = nextIP(ip) {
			ipCopy := make(net.IP, len(ip))
			copy(ipCopy, ip)
			ips = append(ips, ipCopy.String())
		}
		// Drop network and broadcast for IPv4
		if ip.To4() != nil && len(ips) > 2 {
			return ips[1 : len(ips)-1], nil
		}
		return ips, nil
	}
	// Otherwise return as-is (single host)
	return []string{target}, nil
}

// nextIP increments an IP address by 1.
func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

// Run executes a concurrent TCP connect probe on a host or CIDR range.
func Run(ctx app.Context, cfg RunConfig) error {
	if cfg.Target == "" {
		return fmt.Errorf("target cannot be empty")
	}
	if len(cfg.Ports) == 0 {
		cfg.Ports = []int{80, 443}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.PortConcurrency <= 0 {
		cfg.PortConcurrency = 200
	}
	if cfg.HostConcurrency <= 0 {
		cfg.HostConcurrency = 64
	}

	// Expand single host or CIDR into concrete targets.
	targets, err := expandTarget(cfg.Target)
	if err != nil {
		return fmt.Errorf("failed to expand target %q: %w", cfg.Target, err)
	}
	if len(targets) == 0 {
		fmt.Println("No targets to scan after expansion.")
		return nil
	}

	type hostRes struct {
		host    string
		results []Result
		err     error
	}

	hostSem := make(chan struct{}, cfg.HostConcurrency)
	var wg sync.WaitGroup
	resCh := make(chan hostRes, len(targets))

	// Scan each host with port-level concurrency.
	for _, host := range targets {
		host := host
		hostSem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-hostSem; wg.Done() }()
			rs, err := probe(ctx.Ctx, host, cfg.Ports, cfg.Timeout, cfg.PortConcurrency)
			resCh <- hostRes{host: host, results: rs, err: err}
		}()
	}

	wg.Wait()
	close(resCh)

	all := make([]Result, 0, 128)
	for hr := range resCh {
		if hr.err != nil {
			// Non-fatal: print and continue with others.
			fmt.Printf("[!] %s: %v\n", hr.host, hr.err)
			continue
		}
		all = append(all, hr.results...)
	}

	// Stable output: sort by host, then port.
	sort.Slice(all, func(i, j int) bool {
		if all[i].Host == all[j].Host {
			return all[i].Port < all[j].Port
		}
		return all[i].Host < all[j].Host
	})

	// Print to stdout for immediate feedback.
	if len(all) == 0 {
		fmt.Println("No open ports found in provided set.")
	} else {
		for _, r := range all {
			fmt.Printf("%s:%d open\n", r.Host, r.Port)
		}
	}

	// Persist results to workspace.
	timestamp := ctx.Now.Format("20060102-150405")
	jsonlPath := ctx.Workspace.Path("findings", fmt.Sprintf("recon-%s.jsonl", timestamp))
	if err := writeJSONL(jsonlPath, all); err != nil {
		fmt.Printf("[!] failed to write findings JSONL: %v\n", err)
	}

	// Render a markdown report using templates/report.md.tmpl.
	mdPath := ctx.Workspace.Path("reports", fmt.Sprintf("report-recon-%s.md", timestamp))
	data := ReportData{
		Date:      ctx.Now.Format(time.RFC3339),
		Workspace: ctx.Workspace.Path(), // root path
		Findings:  toReportFindings(all),
	}
	if err := renderMarkdownReport(mdPath, filepath.Join("templates", "report.md.tmpl"), data); err != nil {
		fmt.Printf("[!] failed to render markdown report: %v\n", err)
	}

	return nil
}

// probe performs concurrent TCP connect attempts to the given ports.
func probe(ctx context.Context, host string, ports []int, dialTimeout time.Duration, concurrency int) ([]Result, error) {
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	out := make([]Result, 0, 8)

	dialer := &net.Dialer{Timeout: dialTimeout}

	for _, p := range ports {
		p := p
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		default:
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			addr := fmt.Sprintf("%s:%d", host, p)
			cctx, cancel := context.WithTimeout(ctx, dialTimeout)
			conn, err := dialer.DialContext(cctx, "tcp", addr)
			cancel()
			if err == nil {
				_ = conn.Close()
				mu.Lock()
				out = append(out, Result{Host: host, Port: p})
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out, nil
}

// writeJSONL writes results into a JSONL file.
func writeJSONL(path string, results []Result) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func(f *os.File) {
		if cerr := f.Close(); cerr != nil {
			fmt.Printf("[!] %s: %v\n", path, cerr)
		}
	}(f)

	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, r := range results {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return w.Flush()
}

// ReportData is the data model passed to the markdown template.
type ReportData struct {
	Date      string
	Workspace string
	Findings  []reportFinding
}

type reportFinding struct {
	Target   string
	Port     int
	Evidence string
}

func toReportFindings(rs []Result) []reportFinding {
	out := make([]reportFinding, 0, len(rs))
	for _, r := range rs {
		out = append(out, reportFinding{
			Target:   r.Host,
			Port:     r.Port,
			Evidence: "tcp connect succeeded",
		})
	}
	return out
}

// renderMarkdownReport renders templates/report.md.tmpl with data into outPath.
func renderMarkdownReport(outPath, tmplPath string, data ReportData) error {
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	return tmpl.Execute(f, data)
}
