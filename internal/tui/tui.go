package tui

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/tldr-it-stepankutaj/pentakit/internal/app"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/dns"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/http"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/services"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/ssl"
)

const boxWidth = 70

// Ports shared by more than one scan action, hoisted so they can't drift
// between the single-scan and "run all scans" code paths.
var (
	httpPorts = []int{80, 443, 8080, 8443}
	sslPorts  = []int{443, 8443, 993, 995, 465, 636}
)

var spinnerFrames = []string{"◐", "◓", "◑", "◒"}

const spinnerInterval = 120 * time.Millisecond

// tickMsg drives the spinner animation while a scan runs in the background.
type tickMsg time.Time

// scanDoneMsg is delivered when a background scan command finishes.
type scanDoneMsg struct {
	statusType string
	status     string
	duration   time.Duration
}

func tickCmd() tea.Cmd {
	return tea.Tick(spinnerInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// Discovered target from DNS
type target struct {
	domain string
	ips    []string
}

// model is the Bubble Tea model for Pentakit TUI
type model struct {
	appCtx       app.Context
	view         string // domain-input, dns-running, main, running, result
	domain       string
	inputBuffer  string
	targets      []target     // discovered subdomains
	selected     map[int]bool // selected targets for scanning
	cursor       int
	status       string
	statusType   string // info, success, error, running
	lastDuration time.Duration
	dnsResults   []dns.Record
	spinnerFrame int
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch m.view {
		case "domain-input":
			return m.handleDomainInput(msg)
		case "main":
			return m.handleMainMenu(msg)
		case "scanning":
			switch msg.String() {
			case "q", "ctrl+c", "esc":
				return m, tea.Quit
			}
			return m, nil
		case "result":
			m.view = "main"
			m.statusType = "info"
			m.status = "Ready"
			return m, nil
		}
	case tickMsg:
		if m.view != "scanning" {
			return m, nil
		}
		m.spinnerFrame = (m.spinnerFrame + 1) % len(spinnerFrames)
		return m, tickCmd()
	case scanDoneMsg:
		m.view = "result"
		m.statusType = msg.statusType
		m.status = msg.status
		m.lastDuration = msg.duration
		return m, nil
	}
	return m, nil
}

func (m model) handleDomainInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		domain := strings.TrimSpace(m.inputBuffer)
		if domain == "" {
			m.status = "Domain cannot be empty"
			m.statusType = "error"
			return m, nil
		}
		m.domain = domain
		m.inputBuffer = ""
		m.view = "dns-running"
		m.status = "Running DNS enumeration..."
		m.statusType = "running"

		// Run DNS enumeration
		start := time.Now()
		cfg := dns.RunConfig{
			Domain:       m.domain,
			BruteForce:   true,
			ZoneTransfer: true,
			CTLogs:       true, // Use Certificate Transparency logs
			Timeout:      m.appCtx.Config.Timeout,
		}
		results, err := dns.Run(m.appCtx, cfg)
		m.lastDuration = time.Since(start)

		if err != nil {
			m.view = "result"
			m.statusType = "error"
			m.status = err.Error()
			return m, nil
		}

		// Store DNS results and extract targets
		m.dnsResults = results
		m.targets = extractTargets(results, m.domain)
		m.selected = make(map[int]bool)

		// Select all by default
		for i := range m.targets {
			m.selected[i] = true
		}

		m.view = "main"
		m.statusType = "success"
		m.status = fmt.Sprintf("Found %d targets", len(m.targets))
		return m, nil

	case "esc", "ctrl+c":
		return m, tea.Quit
	case "backspace":
		if len(m.inputBuffer) > 0 {
			m.inputBuffer = m.inputBuffer[:len(m.inputBuffer)-1]
		}
	default:
		if len(msg.String()) == 1 {
			m.inputBuffer += msg.String()
		}
	}
	return m, nil
}

func (m model) handleMainMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.targets)-1 {
			m.cursor++
		}
	case " ", "x": // Toggle selection
		m.selected[m.cursor] = !m.selected[m.cursor]
	case "a": // Select all
		for i := range m.targets {
			m.selected[i] = true
		}
	case "n": // Select none
		for i := range m.targets {
			m.selected[i] = false
		}
	case "d": // New domain
		m.view = "domain-input"
		m.inputBuffer = ""
		m.targets = nil
		m.selected = nil
		m.status = ""
		return m, nil
	case "1": // HTTP Analysis
		return m.runHTTPAnalysis()
	case "2": // SSL Analysis
		return m.runSSLAnalysis()
	case "3": // Service Detection
		return m.runServiceDetection()
	case "4": // All scans
		return m.runAllScans()
	case "r": // Generate report
		return m.generateReport()
	}
	return m, nil
}

// startScan transitions into the "scanning" view and kicks off work with
// both a spinner tick and the scan itself, so the Bubble Tea event loop
// keeps redrawing (and keeps accepting q/ctrl+c) while work runs in the
// background instead of blocking Update for the whole scan duration.
func (m model) startScan(label string, work tea.Cmd) (tea.Model, tea.Cmd) {
	m.view = "scanning"
	m.statusType = "running"
	m.status = label
	m.spinnerFrame = 0
	return m, tea.Batch(tickCmd(), work)
}

func (m model) runHTTPAnalysis() (tea.Model, tea.Cmd) {
	selected := m.getSelectedTargets()
	if len(selected) == 0 {
		m.statusType = "error"
		m.status = "No targets selected"
		return m, nil
	}

	cfg := m.appCtx.Config
	return m.startScan(fmt.Sprintf("Scanning %d targets for HTTP endpoints...", len(selected)), func() tea.Msg {
		start := time.Now()
		var successCount, attemptCount int

		for _, t := range selected {
			host := t.domain
			if len(t.ips) > 0 {
				host = t.ips[0]
			}

			for _, port := range httpPorts {
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 3*time.Second)
				if err != nil {
					continue
				}
				_ = conn.Close()

				var url string
				if port == 443 || port == 8443 {
					url = fmt.Sprintf("https://%s:%d", t.domain, port)
					if port == 443 {
						url = fmt.Sprintf("https://%s", t.domain)
					}
				} else {
					url = fmt.Sprintf("http://%s:%d", t.domain, port)
					if port == 80 {
						url = fmt.Sprintf("http://%s", t.domain)
					}
				}

				attemptCount++
				httpCfg := http.RunConfig{
					Target:          url,
					TechFingerprint: true,
					HeaderAnalysis:  true,
					Timeout:         cfg.Timeout,
				}
				if _, err := http.Run(m.appCtx, httpCfg); err == nil {
					successCount++
				}
			}
		}

		return scanDoneMsg{
			statusType: "success",
			status:     fmt.Sprintf("HTTP analysis completed: %d/%d endpoints responded", successCount, attemptCount),
			duration:   time.Since(start),
		}
	})
}

func (m model) runSSLAnalysis() (tea.Model, tea.Cmd) {
	selected := m.getSelectedTargets()
	if len(selected) == 0 {
		m.statusType = "error"
		m.status = "No targets selected"
		return m, nil
	}

	cfg := m.appCtx.Config
	return m.startScan(fmt.Sprintf("Checking SSL/TLS on %d targets...", len(selected)), func() tea.Msg {
		start := time.Now()
		var successCount, attemptCount int

		for _, t := range selected {
			host := t.domain
			if len(t.ips) > 0 {
				host = t.ips[0]
			}

			for _, port := range sslPorts {
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 3*time.Second)
				if err != nil {
					continue
				}
				_ = conn.Close()

				attemptCount++
				sslCfg := ssl.RunConfig{
					Target:   t.domain,
					Port:     port,
					CheckAll: true,
					Timeout:  cfg.Timeout,
				}
				if _, err := ssl.Run(m.appCtx, sslCfg); err == nil {
					successCount++
				}
			}
		}

		return scanDoneMsg{
			statusType: "success",
			status:     fmt.Sprintf("SSL analysis completed: %d/%d endpoints responded", successCount, attemptCount),
			duration:   time.Since(start),
		}
	})
}

func (m model) runServiceDetection() (tea.Model, tea.Cmd) {
	selected := m.getSelectedTargets()
	if len(selected) == 0 {
		m.statusType = "error"
		m.status = "No targets selected"
		return m, nil
	}

	cfg := m.appCtx.Config
	commonPorts := []int{21, 22, 23, 25, 80, 443, 3306, 5432, 8080, 8443}

	return m.startScan(fmt.Sprintf("Running service detection on %d targets...", len(selected)), func() tea.Msg {
		start := time.Now()
		var successCount, failCount int

		for _, t := range selected {
			host := t.domain
			if len(t.ips) > 0 {
				host = t.ips[0]
			}

			svcCfg := services.RunConfig{
				Target:        host,
				Ports:         commonPorts,
				Timeout:       cfg.Timeout,
				GrabBanner:    true,
				DetectVersion: true,
			}
			if _, err := services.Run(m.appCtx, svcCfg); err == nil {
				successCount++
			} else {
				failCount++
			}
		}

		return scanDoneMsg{
			statusType: "success",
			status:     fmt.Sprintf("Service detection completed: %d scanned, %d failed", successCount, failCount),
			duration:   time.Since(start),
		}
	})
}

func (m model) runAllScans() (tea.Model, tea.Cmd) {
	selected := m.getSelectedTargets()
	if len(selected) == 0 {
		m.statusType = "error"
		m.status = "No targets selected"
		return m, nil
	}

	cfg := m.appCtx.Config
	commonPorts := []int{21, 22, 25, 80, 443, 3306, 5432, 8080, 8443}

	return m.startScan(fmt.Sprintf("Running all scans on %d targets...", len(selected)), func() tea.Msg {
		start := time.Now()

		for _, t := range selected {
			host := t.domain
			if len(t.ips) > 0 {
				host = t.ips[0]
			}

			// First: Service detection on all ports
			svcCfg := services.RunConfig{
				Target:        host,
				Ports:         commonPorts,
				Timeout:       cfg.Timeout,
				GrabBanner:    true,
				DetectVersion: true,
			}
			_, _ = services.Run(m.appCtx, svcCfg)

			// Check which HTTP ports are open and analyze
			for _, port := range httpPorts {
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 2*time.Second)
				if err != nil {
					continue
				}
				_ = conn.Close()

				var url string
				if port == 443 || port == 8443 {
					url = fmt.Sprintf("https://%s", t.domain)
					if port != 443 {
						url = fmt.Sprintf("https://%s:%d", t.domain, port)
					}
				} else {
					url = fmt.Sprintf("http://%s", t.domain)
					if port != 80 {
						url = fmt.Sprintf("http://%s:%d", t.domain, port)
					}
				}

				httpCfg := http.RunConfig{
					Target:          url,
					TechFingerprint: true,
					HeaderAnalysis:  true,
					Timeout:         cfg.Timeout,
				}
				_, _ = http.Run(m.appCtx, httpCfg)
			}

			// SSL on 443 if open
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:443", host), 2*time.Second)
			if err == nil {
				_ = conn.Close()
				sslCfg := ssl.RunConfig{
					Target:   t.domain,
					Port:     443,
					CheckAll: true,
					Timeout:  cfg.Timeout,
				}
				_, _ = ssl.Run(m.appCtx, sslCfg)
			}
		}

		return scanDoneMsg{
			statusType: "success",
			status:     fmt.Sprintf("All scans completed on %d targets", len(selected)),
			duration:   time.Since(start),
		}
	})
}

func (m model) generateReport() (tea.Model, tea.Cmd) {
	m.statusType = "info"
	m.status = "Use CLI to generate report: pentakit report --format html"
	return m, nil
}

func (m model) getSelectedTargets() []target {
	var result []target
	for i, t := range m.targets {
		if m.selected[i] {
			result = append(result, t)
		}
	}
	return result
}

func extractTargets(records []dns.Record, baseDomain string) []target {
	targetMap := make(map[string]*target)

	// Add base domain
	targetMap[baseDomain] = &target{domain: baseDomain}

	for _, r := range records {
		switch r.Type {
		case "A", "AAAA":
			if _, ok := targetMap[r.Domain]; !ok {
				targetMap[r.Domain] = &target{domain: r.Domain}
			}
			targetMap[r.Domain].ips = append(targetMap[r.Domain].ips, r.Value)
		case "CNAME":
			// Add the domain that has CNAME record
			if _, ok := targetMap[r.Domain]; !ok {
				targetMap[r.Domain] = &target{domain: r.Domain}
			}
			// Also add the CNAME target (the value it points to)
			cnameTarget := strings.TrimSuffix(r.Value, ".")
			if cnameTarget != "" && cnameTarget != r.Domain {
				if _, ok := targetMap[cnameTarget]; !ok {
					targetMap[cnameTarget] = &target{domain: cnameTarget}
				}
			}
		case "SUBDOMAIN":
			if _, ok := targetMap[r.Domain]; !ok {
				targetMap[r.Domain] = &target{domain: r.Domain, ips: r.Values}
			} else {
				targetMap[r.Domain].ips = append(targetMap[r.Domain].ips, r.Values...)
			}
		}
	}

	var result []target
	for _, t := range targetMap {
		result = append(result, *t)
	}
	// Map iteration order is randomized; sort so the target list (and the
	// cursor position a user remembers) stays stable across runs over the
	// same DNS data.
	sort.Slice(result, func(i, j int) bool { return result[i].domain < result[j].domain })
	return result
}

func (m model) View() string {
	var b strings.Builder

	// Header
	b.WriteString("\n")
	b.WriteString("  ██████╗ ███████╗███╗   ██╗████████╗ █████╗ ██╗  ██╗██╗████████╗\n")
	b.WriteString("  ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██║ ██╔╝██║╚══██╔══╝\n")
	b.WriteString("  ██████╔╝█████╗  ██╔██╗ ██║   ██║   ███████║█████╔╝ ██║   ██║\n")
	b.WriteString("  ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══██║██╔═██╗ ██║   ██║\n")
	b.WriteString("  ██║     ███████╗██║ ╚████║   ██║   ██║  ██║██║  ██╗██║   ██║\n")
	b.WriteString("  ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝\n")
	b.WriteString("                        Penetration Testing Toolkit\n")
	b.WriteString("\n")

	switch m.view {
	case "domain-input":
		b.WriteString(m.viewDomainInput())
	case "dns-running":
		b.WriteString(m.viewDNSRunning())
	case "main":
		b.WriteString(m.viewMain())
	case "scanning":
		b.WriteString(m.viewScanning())
	case "result":
		b.WriteString(m.viewResult())
	}

	return b.String()
}

func (m model) viewDomainInput() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("  ┌─ Enter Domain %s┐\n", strings.Repeat("─", boxWidth-17)))
	b.WriteString(line(""))
	b.WriteString(line("  Enter the target domain to begin reconnaissance:"))
	b.WriteString(line(""))
	b.WriteString(line(fmt.Sprintf("  > %s█", m.inputBuffer)))
	b.WriteString(line(""))
	b.WriteString(line("  DNS enumeration will discover subdomains automatically."))
	b.WriteString(line(""))
	b.WriteString(fmt.Sprintf("  └%s┘\n", strings.Repeat("─", boxWidth)))
	b.WriteString("\n")

	if m.status != "" {
		icon := "○"
		if m.statusType == "error" {
			icon = "✖"
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", icon, m.status))
		b.WriteString("\n")
	}

	b.WriteString("  [Enter] Start DNS scan    [Esc] Quit\n")

	return b.String()
}

func (m model) viewDNSRunning() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("  ┌─ DNS Enumeration %s┐\n", strings.Repeat("─", boxWidth-20)))
	b.WriteString(line(""))
	b.WriteString(line(fmt.Sprintf("  Domain: %s", m.domain)))
	b.WriteString(line(""))
	b.WriteString(line("  ◐ Running DNS enumeration..."))
	b.WriteString(line(""))
	b.WriteString(line("    • Looking up A, AAAA, MX, NS, TXT records"))
	b.WriteString(line("    • Attempting zone transfer"))
	b.WriteString(line("    • Brute-forcing subdomains"))
	b.WriteString(line(""))
	b.WriteString(fmt.Sprintf("  └%s┘\n", strings.Repeat("─", boxWidth)))

	return b.String()
}

func (m model) viewMain() string {
	var b strings.Builder

	// Domain info
	b.WriteString(fmt.Sprintf("  ┌─ Domain: %s %s┐\n", m.domain, strings.Repeat("─", boxWidth-13-len(m.domain))))
	selectedCount := 0
	for _, v := range m.selected {
		if v {
			selectedCount++
		}
	}
	b.WriteString(line(fmt.Sprintf("  Discovered: %d targets    Selected: %d", len(m.targets), selectedCount)))
	b.WriteString(fmt.Sprintf("  └%s┘\n", strings.Repeat("─", boxWidth)))
	b.WriteString("\n")

	// Targets list
	b.WriteString(fmt.Sprintf("  ┌─ Targets %s┐\n", strings.Repeat("─", boxWidth-12)))

	maxVisible := 10
	startIdx := 0
	if m.cursor >= maxVisible {
		startIdx = m.cursor - maxVisible + 1
	}
	endIdx := startIdx + maxVisible
	if endIdx > len(m.targets) {
		endIdx = len(m.targets)
	}

	if startIdx > 0 {
		b.WriteString(line("  ↑ more above"))
	}

	for i := startIdx; i < endIdx; i++ {
		t := m.targets[i]
		cursor := "  "
		if i == m.cursor {
			cursor = "▸ "
		}
		checkbox := "[ ]"
		if m.selected[i] {
			checkbox = "[✓]"
		}

		ipInfo := ""
		if len(t.ips) > 0 {
			if len(t.ips) == 1 {
				ipInfo = fmt.Sprintf(" (%s)", t.ips[0])
			} else {
				ipInfo = fmt.Sprintf(" (%d IPs)", len(t.ips))
			}
		}

		label := t.domain + ipInfo
		if len(label) > boxWidth-12 {
			label = label[:boxWidth-15] + "..."
		}

		b.WriteString(line(fmt.Sprintf("%s%s %s", cursor, checkbox, label)))
	}

	if endIdx < len(m.targets) {
		b.WriteString(line(fmt.Sprintf("  ↓ %d more below", len(m.targets)-endIdx)))
	}

	b.WriteString(fmt.Sprintf("  └%s┘\n", strings.Repeat("─", boxWidth)))
	b.WriteString("\n")

	// Actions
	b.WriteString(fmt.Sprintf("  ┌─ Actions %s┐\n", strings.Repeat("─", boxWidth-12)))
	b.WriteString(line(""))
	b.WriteString(line("  [1] HTTP Analysis      Scan selected for HTTP security"))
	b.WriteString(line("  [2] SSL/TLS Analysis   Check certificates & ciphers"))
	b.WriteString(line("  [3] Service Detection  Port scan & banner grabbing"))
	b.WriteString(line("  [4] Run All Scans      Complete analysis"))
	b.WriteString(line(""))
	b.WriteString(line("  [r] Generate Report    Create report from findings"))
	b.WriteString(line("  [d] New Domain         Start with different domain"))
	b.WriteString(line(""))
	b.WriteString(fmt.Sprintf("  └%s┘\n", strings.Repeat("─", boxWidth)))
	b.WriteString("\n")

	// Status
	icon := "○"
	switch m.statusType {
	case "success":
		icon = "●"
	case "error":
		icon = "✖"
	case "running":
		icon = "◐"
	}
	b.WriteString(fmt.Sprintf("  %s %s\n", icon, m.status))
	b.WriteString("\n")

	// Help
	b.WriteString("  [Space] Toggle  [a] All  [n] None  [↑↓/jk] Navigate  [q] Quit\n")

	return b.String()
}

func (m model) viewScanning() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("  ┌─ Scanning %s┐\n", strings.Repeat("─", boxWidth-13)))
	b.WriteString(line(""))
	b.WriteString(line(fmt.Sprintf("  %s %s", spinnerFrames[m.spinnerFrame], m.status)))
	b.WriteString(line(""))
	b.WriteString(fmt.Sprintf("  └%s┘\n", strings.Repeat("─", boxWidth)))
	b.WriteString("\n")
	b.WriteString("  [q] Quit\n")

	return b.String()
}

func (m model) viewResult() string {
	var b strings.Builder

	icon := "✔"
	title := "COMPLETED"
	if m.statusType == "error" {
		icon = "✖"
		title = "ERROR"
	}

	b.WriteString(fmt.Sprintf("  ┌%s┐\n", strings.Repeat("─", boxWidth)))
	b.WriteString(line(fmt.Sprintf("  %s %s", icon, title)))
	b.WriteString(fmt.Sprintf("  ├%s┤\n", strings.Repeat("─", boxWidth)))
	b.WriteString(line(""))
	b.WriteString(line(fmt.Sprintf("  %s", m.status)))
	b.WriteString(line(""))
	b.WriteString(line(fmt.Sprintf("  Duration: %s", m.lastDuration.Round(time.Millisecond))))
	b.WriteString(line(""))
	b.WriteString(fmt.Sprintf("  └%s┘\n", strings.Repeat("─", boxWidth)))
	b.WriteString("\n")
	b.WriteString("  Press any key to continue...\n")

	return b.String()
}

// Helper functions
func pad(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}

func line(content string) string {
	return fmt.Sprintf("  │%s│\n", pad(content, boxWidth))
}

// Run starts the TUI.
func Run(appCtx app.Context) error {
	initial := model{
		appCtx:     appCtx,
		view:       "domain-input",
		status:     "",
		statusType: "info",
	}
	_, err := tea.NewProgram(initial).Run()
	return err
}
