package reports

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Report represents a comprehensive pentest report.
type Report struct {
	Title             string        `json:"title"`
	ExecutiveSummary  string        `json:"executive_summary"`
	Scope             Scope         `json:"scope"`
	Methodology       string        `json:"methodology,omitempty"`
	Findings          []Finding     `json:"findings"`
	Certificates      []Certificate `json:"certificates,omitempty"`
	NetworkDiagramSVG string        `json:"-"` // SVG content for HTML report
	Statistics        Statistics    `json:"statistics"`
	Recommendations   []string      `json:"recommendations,omitempty"`
	Metadata          Metadata      `json:"metadata"`
}

// Certificate represents an SSL/TLS certificate found during scanning.
type Certificate struct {
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	SerialNumber string   `json:"serial_number,omitempty"`
	SANs         []string `json:"sans,omitempty"`
	IsSelfSigned bool     `json:"is_self_signed"`
	IsExpired    bool     `json:"is_expired"`
	DaysToExpiry int      `json:"days_to_expiry"`
}

// Scope defines the engagement scope.
type Scope struct {
	Targets         []string  `json:"targets"`
	ExcludedTargets []string  `json:"excluded_targets,omitempty"`
	StartDate       time.Time `json:"start_date"`
	EndDate         time.Time `json:"end_date"`
	TestType        string    `json:"test_type"` // internal, external, web, etc.
}

// Finding represents a security finding.
type Finding struct {
	ID            string     `json:"id"`
	Title         string     `json:"title"`
	Severity      string     `json:"severity"` // critical, high, medium, low, info
	CVSS          float64    `json:"cvss,omitempty"`
	CVE           []string   `json:"cve,omitempty"`
	CWE           []string   `json:"cwe,omitempty"`
	Description   string     `json:"description"`
	Impact        string     `json:"impact"`
	Remediation   string     `json:"remediation"`
	Evidence      []Evidence `json:"evidence,omitempty"`
	AffectedHosts []string   `json:"affected_hosts"`
	References    []string   `json:"references,omitempty"`
	Status        string     `json:"status"` // open, confirmed, fixed, accepted
	FoundDate     time.Time  `json:"found_date"`
	Module        string     `json:"module"` // Which module found this
}

// Evidence represents proof of a finding.
type Evidence struct {
	Type        string `json:"type"` // screenshot, request, response, log
	Description string `json:"description"`
	Data        string `json:"data"`
	FilePath    string `json:"file_path,omitempty"`
}

// Statistics contains report statistics.
type Statistics struct {
	TotalFindings      int            `json:"total_findings"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	FindingsByStatus   map[string]int `json:"findings_by_status"`
	HostsScanned       int            `json:"hosts_scanned"`
	PortsScanned       int            `json:"ports_scanned"`
	VulnsExploited     int            `json:"vulns_exploited"`
	ScanDuration       time.Duration  `json:"scan_duration"`
}

// Metadata contains report metadata.
type Metadata struct {
	GeneratedAt   time.Time `json:"generated_at"`
	GeneratedBy   string    `json:"generated_by"`
	ToolVersion   string    `json:"tool_version"`
	WorkspacePath string    `json:"workspace_path"`
	ReportFormat  string    `json:"report_format"`
}

// Builder helps construct reports.
type Builder struct {
	report *Report
}

// NewBuilder creates a new report builder.
func NewBuilder() *Builder {
	return &Builder{
		report: &Report{
			Findings:     make([]Finding, 0),
			Certificates: make([]Certificate, 0),
			Statistics: Statistics{
				FindingsBySeverity: make(map[string]int),
				FindingsByStatus:   make(map[string]int),
			},
		},
	}
}

// AddCertificate adds a certificate to the report.
func (b *Builder) AddCertificate(cert Certificate) *Builder {
	b.report.Certificates = append(b.report.Certificates, cert)
	return b
}

// SetTitle sets the report title.
func (b *Builder) SetTitle(title string) *Builder {
	b.report.Title = title
	return b
}

// SetExecutiveSummary sets the executive summary.
func (b *Builder) SetExecutiveSummary(summary string) *Builder {
	b.report.ExecutiveSummary = summary
	return b
}

// SetScope sets the engagement scope.
func (b *Builder) SetScope(scope Scope) *Builder {
	b.report.Scope = scope
	return b
}

// AddFinding adds a finding to the report.
func (b *Builder) AddFinding(finding Finding) *Builder {
	if finding.ID == "" {
		finding.ID = fmt.Sprintf("FIND-%04d", len(b.report.Findings)+1)
	}
	if finding.FoundDate.IsZero() {
		finding.FoundDate = time.Now()
	}
	if finding.Status == "" {
		finding.Status = "open"
	}
	b.report.Findings = append(b.report.Findings, finding)
	return b
}

// AddRecommendation adds a recommendation.
func (b *Builder) AddRecommendation(rec string) *Builder {
	b.report.Recommendations = append(b.report.Recommendations, rec)
	return b
}

// SetMetadata sets the report metadata.
func (b *Builder) SetMetadata(meta Metadata) *Builder {
	b.report.Metadata = meta
	return b
}

// Build finalizes and returns the report.
func (b *Builder) Build() *Report {
	// Calculate statistics
	b.report.Statistics.TotalFindings = len(b.report.Findings)

	for _, f := range b.report.Findings {
		b.report.Statistics.FindingsBySeverity[f.Severity]++
		b.report.Statistics.FindingsByStatus[f.Status]++
	}

	// Sort findings by severity
	severityOrder := map[string]int{
		"critical": 0,
		"high":     1,
		"medium":   2,
		"low":      3,
		"info":     4,
	}

	sort.Slice(b.report.Findings, func(i, j int) bool {
		return severityOrder[b.report.Findings[i].Severity] < severityOrder[b.report.Findings[j].Severity]
	})

	// Generate executive summary if not provided
	if b.report.ExecutiveSummary == "" {
		b.report.ExecutiveSummary = generateExecutiveSummary(b.report)
	}

	// Set metadata defaults
	if b.report.Metadata.GeneratedAt.IsZero() {
		b.report.Metadata.GeneratedAt = time.Now()
	}
	if b.report.Metadata.GeneratedBy == "" {
		b.report.Metadata.GeneratedBy = "Pentakit"
	}

	return b.report
}

func generateExecutiveSummary(report *Report) string {
	var sb strings.Builder

	critCount := report.Statistics.FindingsBySeverity["critical"]
	highCount := report.Statistics.FindingsBySeverity["high"]
	medCount := report.Statistics.FindingsBySeverity["medium"]
	lowCount := report.Statistics.FindingsBySeverity["low"]

	sb.WriteString(fmt.Sprintf("This penetration test identified %d security findings. ", report.Statistics.TotalFindings))

	if critCount > 0 || highCount > 0 {
		sb.WriteString(fmt.Sprintf("Of particular concern are %d critical and %d high severity vulnerabilities that require immediate attention. ", critCount, highCount))
	}

	if medCount > 0 {
		sb.WriteString(fmt.Sprintf("Additionally, %d medium severity issues were discovered that should be addressed in the near term. ", medCount))
	}

	if lowCount > 0 {
		sb.WriteString(fmt.Sprintf("%d low severity findings were also noted for consideration. ", lowCount))
	}

	if critCount == 0 && highCount == 0 && medCount == 0 && lowCount == 0 {
		sb.WriteString("No significant vulnerabilities were identified during this assessment, indicating a strong security posture.")
	}

	return sb.String()
}

// ExportJSON exports the report as JSON.
func (r *Report) ExportJSON(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return err
	}
	return w.Flush()
}

// ExportMarkdown exports the report as Markdown.
func (r *Report) ExportMarkdown(path string) error {
	tmpl := `# {{ .Title }}

**Generated:** {{ .Metadata.GeneratedAt.Format "2006-01-02 15:04:05" }}
**Generated By:** {{ .Metadata.GeneratedBy }}

---

## Executive Summary

{{ .ExecutiveSummary }}

---

## Scope

**Test Type:** {{ .Scope.TestType }}
**Start Date:** {{ .Scope.StartDate.Format "2006-01-02" }}
**End Date:** {{ .Scope.EndDate.Format "2006-01-02" }}

### Targets
{{ range .Scope.Targets }}
- {{ . }}
{{ end }}

{{ if .Scope.ExcludedTargets }}
### Excluded Targets
{{ range .Scope.ExcludedTargets }}
- {{ . }}
{{ end }}
{{ end }}

---

## Statistics

| Metric | Value |
|--------|-------|
| Total Findings | {{ .Statistics.TotalFindings }} |
| Critical | {{ index .Statistics.FindingsBySeverity "critical" }} |
| High | {{ index .Statistics.FindingsBySeverity "high" }} |
| Medium | {{ index .Statistics.FindingsBySeverity "medium" }} |
| Low | {{ index .Statistics.FindingsBySeverity "low" }} |
| Informational | {{ index .Statistics.FindingsBySeverity "info" }} |

---

## Findings

{{ range .Findings }}
### {{ .ID }}: {{ .Title }}

**Severity:** {{ .Severity | ToUpper }}
{{ if .CVSS }}**CVSS Score:** {{ .CVSS }}  {{ end }}
{{ if .CVE }}**CVE:** {{ Join .CVE ", " }}  {{ end }}
{{ if .CWE }}**CWE:** {{ Join .CWE ", " }}  {{ end }}
**Status:** {{ .Status }}
**Module:** {{ .Module }}

#### Description
{{ .Description }}

#### Impact
{{ .Impact }}

#### Affected Hosts
{{ range .AffectedHosts }}
- {{ . }}
{{ end }}

#### Remediation
{{ .Remediation }}

{{ if .Evidence }}
#### Evidence
{{ range .Evidence }}
**{{ .Type }}:** {{ .Description }}
` + "```" + `
{{ .Data }}
` + "```" + `
{{ end }}
{{ end }}

{{ if .References }}
#### References
{{ range .References }}
- {{ . }}
{{ end }}
{{ end }}

---

{{ end }}

{{ if .Certificates }}
## SSL/TLS Certificates

| Host | Subject | Issuer | Valid From | Valid Until | Status |
|------|---------|--------|------------|-------------|--------|
{{ range .Certificates }}| {{ .Host }}:{{ .Port }} | {{ .Subject }} | {{ .Issuer }} | {{ .NotBefore }} | {{ .NotAfter }} | {{ if .IsExpired }}EXPIRED{{ else if .IsSelfSigned }}Self-Signed{{ else if lt .DaysToExpiry 30 }}Expires in {{ .DaysToExpiry }} days{{ else }}Valid ({{ .DaysToExpiry }} days){{ end }} |
{{ end }}
{{ end }}

{{ if .Recommendations }}
## Recommendations

{{ range $i, $rec := .Recommendations }}
{{ $i | Inc }}. {{ $rec }}
{{ end }}
{{ end }}

---

*Report generated by Pentakit*
`

	funcMap := template.FuncMap{
		"ToUpper": strings.ToUpper,
		"Join":    strings.Join,
		"Inc":     func(i int) int { return i + 1 },
		"lt":      func(a, b int) bool { return a < b },
	}

	t, err := template.New("report").Funcs(funcMap).Parse(tmpl)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return t.Execute(f, r)
}

// ExportHTML exports the report as HTML.
func (r *Report) ExportHTML(path string) error {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ .Title }}</title>
    <style>
        :root {
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #28a745;
            --info: #17a2b8;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; border-bottom: 1px solid #bdc3c7; padding-bottom: 5px; margin-top: 30px; }
        h3 { color: #7f8c8d; }
        .meta { color: #7f8c8d; font-size: 0.9em; margin-bottom: 20px; }
        .summary { background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .stats { display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }
        .stat-card {
            background: white;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            min-width: 120px;
            text-align: center;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
            text-decoration: none;
            color: inherit;
        }
        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }
        .stat-card.critical { border-left: 4px solid var(--critical); }
        .stat-card.high { border-left: 4px solid var(--high); }
        .stat-card.medium { border-left: 4px solid var(--medium); }
        .stat-card.low { border-left: 4px solid var(--low); }
        .stat-card.info { border-left: 4px solid var(--info); }
        .stat-value { font-size: 2em; font-weight: bold; }
        .stat-label { color: #7f8c8d; font-size: 0.9em; }
        .finding {
            border: 1px solid #ddd;
            border-radius: 5px;
            margin: 20px 0;
            overflow: hidden;
        }
        .finding-header {
            padding: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .finding-header.critical { background: var(--critical); color: white; }
        .finding-header.high { background: var(--high); color: white; }
        .finding-header.medium { background: var(--medium); color: #333; }
        .finding-header.low { background: var(--low); color: white; }
        .finding-header.info { background: var(--info); color: white; }
        .finding-body { padding: 20px; }
        .finding-meta { display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 15px; font-size: 0.9em; }
        .finding-meta span { background: #f8f9fa; padding: 3px 8px; border-radius: 3px; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.8em; }
        .evidence { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .evidence pre { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; }
        ul { padding-left: 20px; }
        .recommendations { background: #e8f4f8; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .recommendations ol { padding-left: 20px; }
        .footer { text-align: center; color: #7f8c8d; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; }
        .severity-section { scroll-margin-top: 20px; padding-top: 10px; }
        .severity-section h3 { display: flex; align-items: center; gap: 10px; }
        .severity-section h3::before { content: ""; display: inline-block; width: 12px; height: 12px; border-radius: 2px; }
        .severity-section.critical h3::before { background: var(--critical); }
        .severity-section.high h3::before { background: var(--high); }
        .severity-section.medium h3::before { background: var(--medium); }
        .severity-section.low h3::before { background: var(--low); }
        .severity-section.info h3::before { background: var(--info); }
        .cert-table { font-size: 0.9em; }
        .cert-table .expired { color: var(--critical); font-weight: bold; }
        .cert-table .expiring-soon { color: var(--high); }
        .cert-table .self-signed { color: var(--medium); }
        .cert-table .ok { color: var(--low); }
        .network-diagram {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
            overflow-x: auto;
        }
        .network-diagram svg {
            max-width: 100%;
            height: auto;
            display: block;
            margin: 0 auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{ .Title }}</h1>
        <div class="meta">
            Generated: {{ .Metadata.GeneratedAt.Format "2006-01-02 15:04:05" }} |
            Tool: {{ .Metadata.GeneratedBy }}
        </div>

        <h2>Executive Summary</h2>
        <div class="summary">
            <p>{{ .ExecutiveSummary }}</p>
        </div>

        <h2>Statistics</h2>
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{{ .Statistics.TotalFindings }}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <a href="#findings-critical" class="stat-card critical">
                <div class="stat-value">{{ index .Statistics.FindingsBySeverity "critical" }}</div>
                <div class="stat-label">Critical</div>
            </a>
            <a href="#findings-high" class="stat-card high">
                <div class="stat-value">{{ index .Statistics.FindingsBySeverity "high" }}</div>
                <div class="stat-label">High</div>
            </a>
            <a href="#findings-medium" class="stat-card medium">
                <div class="stat-value">{{ index .Statistics.FindingsBySeverity "medium" }}</div>
                <div class="stat-label">Medium</div>
            </a>
            <a href="#findings-low" class="stat-card low">
                <div class="stat-value">{{ index .Statistics.FindingsBySeverity "low" }}</div>
                <div class="stat-label">Low</div>
            </a>
            <a href="#findings-info" class="stat-card info">
                <div class="stat-value">{{ index .Statistics.FindingsBySeverity "info" }}</div>
                <div class="stat-label">Info</div>
            </a>
        </div>

        <h2>Scope</h2>
        <table>
            <tr><th>Test Type</th><td>{{ .Scope.TestType }}</td></tr>
            <tr><th>Start Date</th><td>{{ .Scope.StartDate.Format "2006-01-02" }}</td></tr>
            <tr><th>End Date</th><td>{{ .Scope.EndDate.Format "2006-01-02" }}</td></tr>
            <tr><th>Targets</th><td>{{ Join .Scope.Targets ", " }}</td></tr>
        </table>

        <h2>Findings</h2>

        {{ if gt (index .Statistics.FindingsBySeverity "critical") 0 }}
        <div id="findings-critical" class="severity-section critical">
            <h3>Critical Findings</h3>
            {{ range .Findings }}{{ if eq .Severity "critical" }}
            <div class="finding">
                <div class="finding-header critical">
                    <span><strong>{{ .ID }}:</strong> {{ .Title }}</span>
                    <span class="badge">CRITICAL</span>
                </div>
                <div class="finding-body">
                    <div class="finding-meta">
                        {{ if .CVSS }}<span>CVSS: {{ .CVSS }}</span>{{ end }}
                        {{ if .CVE }}<span>CVE: {{ Join .CVE ", " }}</span>{{ end }}
                        <span>Status: {{ .Status }}</span>
                        <span>Module: {{ .Module }}</span>
                    </div>
                    <h4>Description</h4><p>{{ .Description }}</p>
                    <h4>Impact</h4><p>{{ .Impact }}</p>
                    <h4>Affected Hosts</h4><ul>{{ range .AffectedHosts }}<li>{{ . }}</li>{{ end }}</ul>
                    <h4>Remediation</h4><p>{{ .Remediation }}</p>
                    {{ if .Evidence }}<h4>Evidence</h4>{{ range .Evidence }}<div class="evidence"><strong>{{ .Type }}:</strong> {{ .Description }}{{ if .Data }}<pre>{{ .Data }}</pre>{{ end }}</div>{{ end }}{{ end }}
                </div>
            </div>
            {{ end }}{{ end }}
        </div>
        {{ end }}

        {{ if gt (index .Statistics.FindingsBySeverity "high") 0 }}
        <div id="findings-high" class="severity-section high">
            <h3>High Findings</h3>
            {{ range .Findings }}{{ if eq .Severity "high" }}
            <div class="finding">
                <div class="finding-header high">
                    <span><strong>{{ .ID }}:</strong> {{ .Title }}</span>
                    <span class="badge">HIGH</span>
                </div>
                <div class="finding-body">
                    <div class="finding-meta">
                        {{ if .CVSS }}<span>CVSS: {{ .CVSS }}</span>{{ end }}
                        {{ if .CVE }}<span>CVE: {{ Join .CVE ", " }}</span>{{ end }}
                        <span>Status: {{ .Status }}</span>
                        <span>Module: {{ .Module }}</span>
                    </div>
                    <h4>Description</h4><p>{{ .Description }}</p>
                    <h4>Impact</h4><p>{{ .Impact }}</p>
                    <h4>Affected Hosts</h4><ul>{{ range .AffectedHosts }}<li>{{ . }}</li>{{ end }}</ul>
                    <h4>Remediation</h4><p>{{ .Remediation }}</p>
                    {{ if .Evidence }}<h4>Evidence</h4>{{ range .Evidence }}<div class="evidence"><strong>{{ .Type }}:</strong> {{ .Description }}{{ if .Data }}<pre>{{ .Data }}</pre>{{ end }}</div>{{ end }}{{ end }}
                </div>
            </div>
            {{ end }}{{ end }}
        </div>
        {{ end }}

        {{ if gt (index .Statistics.FindingsBySeverity "medium") 0 }}
        <div id="findings-medium" class="severity-section medium">
            <h3>Medium Findings</h3>
            {{ range .Findings }}{{ if eq .Severity "medium" }}
            <div class="finding">
                <div class="finding-header medium">
                    <span><strong>{{ .ID }}:</strong> {{ .Title }}</span>
                    <span class="badge">MEDIUM</span>
                </div>
                <div class="finding-body">
                    <div class="finding-meta">
                        {{ if .CVSS }}<span>CVSS: {{ .CVSS }}</span>{{ end }}
                        {{ if .CVE }}<span>CVE: {{ Join .CVE ", " }}</span>{{ end }}
                        <span>Status: {{ .Status }}</span>
                        <span>Module: {{ .Module }}</span>
                    </div>
                    <h4>Description</h4><p>{{ .Description }}</p>
                    <h4>Impact</h4><p>{{ .Impact }}</p>
                    <h4>Affected Hosts</h4><ul>{{ range .AffectedHosts }}<li>{{ . }}</li>{{ end }}</ul>
                    <h4>Remediation</h4><p>{{ .Remediation }}</p>
                    {{ if .Evidence }}<h4>Evidence</h4>{{ range .Evidence }}<div class="evidence"><strong>{{ .Type }}:</strong> {{ .Description }}{{ if .Data }}<pre>{{ .Data }}</pre>{{ end }}</div>{{ end }}{{ end }}
                </div>
            </div>
            {{ end }}{{ end }}
        </div>
        {{ end }}

        {{ if gt (index .Statistics.FindingsBySeverity "low") 0 }}
        <div id="findings-low" class="severity-section low">
            <h3>Low Findings</h3>
            {{ range .Findings }}{{ if eq .Severity "low" }}
            <div class="finding">
                <div class="finding-header low">
                    <span><strong>{{ .ID }}:</strong> {{ .Title }}</span>
                    <span class="badge">LOW</span>
                </div>
                <div class="finding-body">
                    <div class="finding-meta">
                        {{ if .CVSS }}<span>CVSS: {{ .CVSS }}</span>{{ end }}
                        {{ if .CVE }}<span>CVE: {{ Join .CVE ", " }}</span>{{ end }}
                        <span>Status: {{ .Status }}</span>
                        <span>Module: {{ .Module }}</span>
                    </div>
                    <h4>Description</h4><p>{{ .Description }}</p>
                    <h4>Impact</h4><p>{{ .Impact }}</p>
                    <h4>Affected Hosts</h4><ul>{{ range .AffectedHosts }}<li>{{ . }}</li>{{ end }}</ul>
                    <h4>Remediation</h4><p>{{ .Remediation }}</p>
                    {{ if .Evidence }}<h4>Evidence</h4>{{ range .Evidence }}<div class="evidence"><strong>{{ .Type }}:</strong> {{ .Description }}{{ if .Data }}<pre>{{ .Data }}</pre>{{ end }}</div>{{ end }}{{ end }}
                </div>
            </div>
            {{ end }}{{ end }}
        </div>
        {{ end }}

        {{ if gt (index .Statistics.FindingsBySeverity "info") 0 }}
        <div id="findings-info" class="severity-section info">
            <h3>Informational Findings</h3>
            {{ range .Findings }}{{ if eq .Severity "info" }}
            <div class="finding">
                <div class="finding-header info">
                    <span><strong>{{ .ID }}:</strong> {{ .Title }}</span>
                    <span class="badge">INFO</span>
                </div>
                <div class="finding-body">
                    <div class="finding-meta">
                        <span>Status: {{ .Status }}</span>
                        <span>Module: {{ .Module }}</span>
                    </div>
                    <h4>Description</h4><p>{{ .Description }}</p>
                    <h4>Affected Hosts</h4><ul>{{ range .AffectedHosts }}<li>{{ . }}</li>{{ end }}</ul>
                    <h4>Remediation</h4><p>{{ .Remediation }}</p>
                </div>
            </div>
            {{ end }}{{ end }}
        </div>
        {{ end }}

        {{ if .NetworkDiagramSVG }}
        <h2>Network Topology</h2>
        <div class="network-diagram">
            {{ .NetworkDiagramSVG | safeHTML }}
        </div>
        {{ end }}

        {{ if .Certificates }}
        <h2>SSL/TLS Certificates</h2>
        <table class="cert-table">
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Subject</th>
                    <th>Issuer</th>
                    <th>Valid From</th>
                    <th>Valid Until</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
            {{ range .Certificates }}
                <tr>
                    <td>{{ .Host }}:{{ .Port }}</td>
                    <td>{{ .Subject }}</td>
                    <td>{{ .Issuer }}</td>
                    <td>{{ .NotBefore }}</td>
                    <td>{{ .NotAfter }}</td>
                    <td>
                        {{ if .IsExpired }}<span class="expired">EXPIRED</span>
                        {{ else if .IsSelfSigned }}<span class="self-signed">Self-Signed</span>
                        {{ else if lt .DaysToExpiry 30 }}<span class="expiring-soon">Expires in {{ .DaysToExpiry }} days</span>
                        {{ else }}<span class="ok">Valid ({{ .DaysToExpiry }} days)</span>
                        {{ end }}
                    </td>
                </tr>
            {{ end }}
            </tbody>
        </table>
        {{ end }}

        {{ if .Recommendations }}
        <h2>Recommendations</h2>
        <div class="recommendations">
            <ol>
            {{ range .Recommendations }}
                <li>{{ . }}</li>
            {{ end }}
            </ol>
        </div>
        {{ end }}

        <div class="footer">
            <p>Report generated by Pentakit</p>
        </div>
    </div>
</body>
</html>`

	funcMap := template.FuncMap{
		"ToUpper":  strings.ToUpper,
		"Join":     strings.Join,
		"gt":       func(a, b int) bool { return a > b },
		"lt":       func(a, b int) bool { return a < b },
		"safeHTML": func(s string) template.HTML { return template.HTML(s) },
	}

	t, err := template.New("report").Funcs(funcMap).Parse(tmpl)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return t.Execute(f, r)
}

// RenderToString renders the report to a string in the specified format.
func (r *Report) RenderToString(format string) (string, error) {
	var buf bytes.Buffer

	switch format {
	case "json":
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return "", err
		}
	case "text":
		buf.WriteString(fmt.Sprintf("PENTEST REPORT: %s\n", r.Title))
		buf.WriteString(strings.Repeat("=", 60) + "\n\n")
		buf.WriteString(fmt.Sprintf("Generated: %s\n", r.Metadata.GeneratedAt.Format(time.RFC3339)))
		buf.WriteString(fmt.Sprintf("Total Findings: %d\n\n", r.Statistics.TotalFindings))

		buf.WriteString("FINDINGS:\n")
		buf.WriteString(strings.Repeat("-", 40) + "\n")
		for _, f := range r.Findings {
			buf.WriteString(fmt.Sprintf("\n[%s] %s: %s\n", strings.ToUpper(f.Severity), f.ID, f.Title))
			buf.WriteString(fmt.Sprintf("    Description: %s\n", f.Description))
			buf.WriteString(fmt.Sprintf("    Impact: %s\n", f.Impact))
			buf.WriteString(fmt.Sprintf("    Remediation: %s\n", f.Remediation))
		}
	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}

	return buf.String(), nil
}

// MergeFindings merges findings from multiple sources, deduplicating by title.
func MergeFindings(findings ...[]Finding) []Finding {
	seen := make(map[string]bool)
	var merged []Finding

	for _, fs := range findings {
		for _, f := range fs {
			key := f.Title + strings.Join(f.AffectedHosts, ",")
			if !seen[key] {
				seen[key] = true
				merged = append(merged, f)
			}
		}
	}

	return merged
}

// SeverityToScore converts severity string to numeric score.
func SeverityToScore(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// CVSSToSeverity converts CVSS score to severity string.
func CVSSToSeverity(cvss float64) string {
	switch {
	case cvss >= 9.0:
		return "critical"
	case cvss >= 7.0:
		return "high"
	case cvss >= 4.0:
		return "medium"
	case cvss >= 0.1:
		return "low"
	default:
		return "info"
	}
}

// Legacy support for old ReportData
type ReportData struct {
	Date      string
	Workspace string
	Findings  []struct {
		Target   string
		Port     int
		Evidence string
	}
}

// RenderMarkdownReport renders templates/report.md.tmpl with data into outPath.
func RenderMarkdownReport(outPath string, data ReportData) error {
	tmplPath := filepath.Join("templates", "report.md.tmpl")

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
	defer f.Close()

	return tmpl.Execute(f, data)
}
