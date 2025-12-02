package reports

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tldr-it-stepankutaj/pentakit/internal/workspace"
)

// Collector aggregates findings from all modules in a workspace.
type Collector struct {
	ws workspace.Handle
}

// NewCollector creates a new findings collector.
func NewCollector(ws workspace.Handle) *Collector {
	return &Collector{ws: ws}
}

// CollectAll gathers all findings from the workspace and builds a comprehensive report.
func (c *Collector) CollectAll() (*Report, error) {
	builder := NewBuilder()

	// Collect from all sources
	reconFindings, _ := c.collectRecon()
	serviceFindings, _ := c.collectServices()
	dnsFindings, _ := c.collectDNS()
	httpFindings, _ := c.collectHTTP()
	sslFindings, certs := c.collectSSL()
	nucleiFindings, _ := c.collectNuclei()

	// Add all findings
	allFindings := append(reconFindings, serviceFindings...)
	allFindings = append(allFindings, dnsFindings...)
	allFindings = append(allFindings, httpFindings...)
	allFindings = append(allFindings, sslFindings...)
	allFindings = append(allFindings, nucleiFindings...)

	for _, f := range allFindings {
		builder.AddFinding(f)
	}

	// Add certificates
	for _, cert := range certs {
		builder.AddCertificate(cert)
	}

	// Collect unique targets
	targets := c.collectTargets(allFindings)

	builder.SetTitle("Penetration Test Report")
	builder.SetScope(Scope{
		Targets:   targets,
		StartDate: time.Now().Add(-24 * time.Hour), // Approximate
		EndDate:   time.Now(),
		TestType:  "External",
	})

	// Add recommendations based on findings
	c.addRecommendations(builder, allFindings)

	builder.SetMetadata(Metadata{
		GeneratedAt:   time.Now(),
		GeneratedBy:   "Pentakit",
		ToolVersion:   "1.0.0",
		WorkspacePath: c.ws.Root,
		ReportFormat:  "comprehensive",
	})

	return builder.Build(), nil
}

func (c *Collector) collectTargets(findings []Finding) []string {
	targetSet := make(map[string]bool)
	for _, f := range findings {
		for _, h := range f.AffectedHosts {
			targetSet[h] = true
		}
	}

	var targets []string
	for t := range targetSet {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	return targets
}

func (c *Collector) addRecommendations(builder *Builder, findings []Finding) {
	hasSSL := false
	hasHTTP := false
	hasOpenPorts := false
	hasServices := false

	for _, f := range findings {
		switch f.Module {
		case "ssl":
			hasSSL = true
		case "http":
			hasHTTP = true
		case "recon":
			hasOpenPorts = true
		case "services":
			hasServices = true
		}
	}

	if hasSSL {
		builder.AddRecommendation("Review SSL/TLS configuration and update to TLS 1.3 where possible")
		builder.AddRecommendation("Replace self-signed certificates with certificates from trusted CAs")
	}
	if hasHTTP {
		builder.AddRecommendation("Implement missing security headers (HSTS, CSP, X-Frame-Options, etc.)")
		builder.AddRecommendation("Disable server version disclosure in HTTP responses")
	}
	if hasOpenPorts {
		builder.AddRecommendation("Review open ports and close unnecessary services")
		builder.AddRecommendation("Implement firewall rules to restrict access to sensitive ports")
	}
	if hasServices {
		builder.AddRecommendation("Update services to latest stable versions")
		builder.AddRecommendation("Implement network segmentation for sensitive services")
	}
}

// collectRecon reads recon JSONL files
func (c *Collector) collectRecon() ([]Finding, error) {
	var findings []Finding
	pattern := filepath.Join(c.ws.Root, "findings", "recon-*.jsonl")
	files, _ := filepath.Glob(pattern)

	for _, file := range files {
		results, err := readJSONL[reconResult](file)
		if err != nil {
			continue
		}

		// Group by target
		targetPorts := make(map[string][]int)
		for _, r := range results {
			if r.Open {
				targetPorts[r.Target] = append(targetPorts[r.Target], r.Port)
			}
		}

		for target, ports := range targetPorts {
			sort.Ints(ports)
			var portStrs []string
			for _, p := range ports {
				portStrs = append(portStrs, fmt.Sprintf("%d", p))
			}

			findings = append(findings, Finding{
				Title:         fmt.Sprintf("Open Ports Detected on %s", target),
				Severity:      "info",
				Description:   fmt.Sprintf("Port scan identified %d open ports: %s", len(ports), strings.Join(portStrs, ", ")),
				Impact:        "Open ports may expose services to potential attackers. Each service should be evaluated for necessity and security configuration.",
				Remediation:   "Close unnecessary ports and ensure all exposed services are properly secured and updated.",
				AffectedHosts: []string{target},
				Module:        "recon",
				Evidence: []Evidence{{
					Type:        "scan",
					Description: "Port scan results",
					Data:        fmt.Sprintf("Open ports: %s", strings.Join(portStrs, ", ")),
				}},
			})
		}
	}

	return findings, nil
}

type reconResult struct {
	Target string `json:"target"`
	Port   int    `json:"port"`
	Open   bool   `json:"open"`
}

// collectServices reads service detection JSONL files
func (c *Collector) collectServices() ([]Finding, error) {
	var findings []Finding
	pattern := filepath.Join(c.ws.Root, "findings", "services-*.jsonl")
	files, _ := filepath.Glob(pattern)

	for _, file := range files {
		results, err := readJSONL[serviceResult](file)
		if err != nil {
			continue
		}

		for _, r := range results {
			findings = append(findings, Finding{
				Title:         fmt.Sprintf("%s Service on %s:%d", r.Service, r.Host, r.Port),
				Severity:      "info",
				Description:   fmt.Sprintf("Detected %s service (version: %s) on port %d", r.Service, r.Version, r.Port),
				Impact:        "Service information can be used by attackers to identify potential vulnerabilities.",
				Remediation:   "Ensure service is updated to the latest version and properly configured.",
				AffectedHosts: []string{fmt.Sprintf("%s:%d", r.Host, r.Port)},
				Module:        "services",
				Evidence: []Evidence{{
					Type:        "banner",
					Description: "Service banner",
					Data:        r.Banner,
				}},
			})
		}
	}

	return findings, nil
}

type serviceResult struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Service string `json:"service"`
	Version string `json:"version"`
	Banner  string `json:"banner"`
}

// collectDNS reads DNS JSONL files
func (c *Collector) collectDNS() ([]Finding, error) {
	var findings []Finding
	pattern := filepath.Join(c.ws.Root, "findings", "dns-*.jsonl")
	files, _ := filepath.Glob(pattern)

	for _, file := range files {
		results, err := readJSONL[dnsResult](file)
		if err != nil {
			continue
		}

		// Collect subdomains
		var subdomains []string
		var domain string
		for _, r := range results {
			if r.Type == "SUBDOMAIN" {
				subdomains = append(subdomains, r.Domain)
			}
			if domain == "" && r.Domain != "" {
				parts := strings.Split(r.Domain, ".")
				if len(parts) >= 2 {
					domain = strings.Join(parts[len(parts)-2:], ".")
				}
			}
		}

		if len(subdomains) > 0 {
			findings = append(findings, Finding{
				Title:         fmt.Sprintf("Subdomains Discovered for %s", domain),
				Severity:      "info",
				Description:   fmt.Sprintf("DNS enumeration discovered %d subdomains", len(subdomains)),
				Impact:        "Subdomains may expose additional attack surface including development, staging, or administrative interfaces.",
				Remediation:   "Review all discovered subdomains and ensure they are properly secured or decommissioned if not needed.",
				AffectedHosts: subdomains,
				Module:        "dns",
				Evidence: []Evidence{{
					Type:        "dns",
					Description: "Discovered subdomains",
					Data:        strings.Join(subdomains, "\n"),
				}},
			})
		}
	}

	return findings, nil
}

type dnsResult struct {
	Type   string   `json:"type"`
	Domain string   `json:"domain"`
	Value  string   `json:"value"`
	Values []string `json:"values"`
}

// collectHTTP reads HTTP JSONL files
func (c *Collector) collectHTTP() ([]Finding, error) {
	var findings []Finding
	pattern := filepath.Join(c.ws.Root, "findings", "http-*.jsonl")
	files, _ := filepath.Glob(pattern)

	for _, file := range files {
		results, err := readJSONL[httpResult](file)
		if err != nil {
			continue
		}

		for _, r := range results {
			// Security headers finding
			if len(r.SecurityIssues) > 0 {
				findings = append(findings, Finding{
					Title:         fmt.Sprintf("Missing Security Headers on %s", r.URL),
					Severity:      "medium",
					Description:   fmt.Sprintf("HTTP security analysis identified %d security issues", len(r.SecurityIssues)),
					Impact:        "Missing security headers can expose the application to various attacks including XSS, clickjacking, and MIME sniffing.",
					Remediation:   "Implement recommended security headers: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, etc.",
					AffectedHosts: []string{r.URL},
					Module:        "http",
					Evidence: []Evidence{{
						Type:        "headers",
						Description: "Security issues",
						Data:        strings.Join(r.SecurityIssues, "\n"),
					}},
				})
			}

			// Server disclosure
			if r.Server != "" {
				findings = append(findings, Finding{
					Title:         fmt.Sprintf("Server Version Disclosure on %s", r.URL),
					Severity:      "low",
					Description:   fmt.Sprintf("Server header reveals: %s", r.Server),
					Impact:        "Server version disclosure helps attackers identify potential vulnerabilities specific to the software version.",
					Remediation:   "Configure the web server to hide or obfuscate the Server header.",
					AffectedHosts: []string{r.URL},
					Module:        "http",
					Evidence: []Evidence{{
						Type:        "header",
						Description: "Server header",
						Data:        r.Server,
					}},
				})
			}

			// Technologies
			if len(r.Technologies) > 0 {
				findings = append(findings, Finding{
					Title:         fmt.Sprintf("Technologies Detected on %s", r.URL),
					Severity:      "info",
					Description:   fmt.Sprintf("Detected technologies: %s", strings.Join(r.Technologies, ", ")),
					Impact:        "Technology stack information can help attackers identify potential vulnerabilities.",
					Remediation:   "Ensure all detected technologies are updated and properly configured.",
					AffectedHosts: []string{r.URL},
					Module:        "http",
					Evidence: []Evidence{{
						Type:        "fingerprint",
						Description: "Detected technologies",
						Data:        strings.Join(r.Technologies, "\n"),
					}},
				})
			}
		}
	}

	return findings, nil
}

type httpResult struct {
	URL            string            `json:"url"`
	StatusCode     int               `json:"status_code"`
	Server         string            `json:"server"`
	Technologies   []string          `json:"technologies"`
	SecurityIssues []string          `json:"security_issues"`
	Headers        map[string]string `json:"headers"`
}

// collectSSL reads SSL JSON files and returns findings and certificates
func (c *Collector) collectSSL() ([]Finding, []Certificate) {
	var findings []Finding
	var certs []Certificate
	pattern := filepath.Join(c.ws.Root, "findings", "ssl-*.json")
	files, _ := filepath.Glob(pattern)

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var r sslResult
		if err := json.Unmarshal(data, &r); err != nil {
			continue
		}

		host := fmt.Sprintf("%s:%d", r.Host, r.Port)

		// Collect certificate info
		cert := Certificate{
			Host:         r.Host,
			Port:         r.Port,
			Subject:      r.Certificate.Subject,
			Issuer:       r.Certificate.Issuer,
			NotBefore:    r.Certificate.NotBefore,
			NotAfter:     r.Certificate.NotAfter,
			SerialNumber: r.Certificate.SerialNumber,
			SANs:         r.Certificate.SANs,
			IsSelfSigned: r.Certificate.IsSelfSigned,
		}

		// Calculate days to expiry
		if r.Certificate.NotAfter != "" {
			if expiry, err := time.Parse("2006-01-02", r.Certificate.NotAfter); err == nil {
				daysLeft := int(time.Until(expiry).Hours() / 24)
				cert.DaysToExpiry = daysLeft
				cert.IsExpired = daysLeft < 0
			} else if expiry, err := time.Parse(time.RFC3339, r.Certificate.NotAfter); err == nil {
				daysLeft := int(time.Until(expiry).Hours() / 24)
				cert.DaysToExpiry = daysLeft
				cert.IsExpired = daysLeft < 0
			}
		}

		certs = append(certs, cert)

		// Certificate findings
		if r.Certificate.IsSelfSigned {
			findings = append(findings, Finding{
				Title:         fmt.Sprintf("Self-Signed Certificate on %s", host),
				Severity:      "medium",
				Description:   "Server uses a self-signed SSL/TLS certificate",
				Impact:        "Self-signed certificates can lead to man-in-the-middle attacks and reduce user trust.",
				Remediation:   "Obtain a certificate from a trusted Certificate Authority (CA).",
				AffectedHosts: []string{host},
				Module:        "ssl",
				Evidence: []Evidence{{
					Type:        "certificate",
					Description: "Certificate details",
					Data:        fmt.Sprintf("Subject: %s\nIssuer: %s\nExpires: %s", r.Certificate.Subject, r.Certificate.Issuer, r.Certificate.NotAfter),
				}},
			})
		}

		// TLS version findings
		hasTLS13 := false
		for _, v := range r.SupportedVersions {
			if v == "TLS 1.3" {
				hasTLS13 = true
			}
		}
		if !hasTLS13 {
			findings = append(findings, Finding{
				Title:         fmt.Sprintf("TLS 1.3 Not Supported on %s", host),
				Severity:      "low",
				Description:   fmt.Sprintf("Server supports: %s but not TLS 1.3", strings.Join(r.SupportedVersions, ", ")),
				Impact:        "TLS 1.3 provides improved security and performance over older versions.",
				Remediation:   "Enable TLS 1.3 support on the server.",
				AffectedHosts: []string{host},
				Module:        "ssl",
			})
		}

		// Vulnerabilities from scan
		for _, v := range r.Vulnerabilities {
			findings = append(findings, Finding{
				Title:         fmt.Sprintf("%s on %s", v.Name, host),
				Severity:      v.Severity,
				Description:   v.Description,
				Impact:        "This vulnerability may allow attackers to compromise encrypted communications.",
				Remediation:   "Update SSL/TLS configuration to mitigate this vulnerability.",
				AffectedHosts: []string{host},
				Module:        "ssl",
			})
		}
	}

	return findings, certs
}

type sslResult struct {
	Host              string         `json:"host"`
	Port              int            `json:"port"`
	TLSVersion        string         `json:"tls_version"`
	Certificate       sslCertificate `json:"certificate"`
	SupportedVersions []string       `json:"supported_versions"`
	SupportedCiphers  []string       `json:"supported_ciphers"`
	Vulnerabilities   []sslVuln      `json:"vulnerabilities"`
	Warnings          []string       `json:"warnings"`
}

type sslCertificate struct {
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	SerialNumber string   `json:"serial_number"`
	SANs         []string `json:"sans"`
	IsSelfSigned bool     `json:"is_self_signed"`
}

type sslVuln struct {
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// collectNuclei reads Nuclei JSONL files
func (c *Collector) collectNuclei() ([]Finding, error) {
	var findings []Finding
	pattern := filepath.Join(c.ws.Root, "findings", "nuclei-*.jsonl")
	files, _ := filepath.Glob(pattern)

	for _, file := range files {
		results, err := readJSONL[nucleiResult](file)
		if err != nil {
			continue
		}

		for _, r := range results {
			findings = append(findings, Finding{
				Title:         r.Info.Name,
				Severity:      strings.ToLower(r.Info.Severity),
				CVE:           r.Info.Classification.CVEId,
				CWE:           r.Info.Classification.CWEId,
				CVSS:          r.Info.Classification.CVSSScore,
				Description:   r.Info.Description,
				Impact:        "This vulnerability may allow attackers to compromise the affected system.",
				Remediation:   "Apply vendor patches or implement recommended mitigations.",
				AffectedHosts: []string{r.Host},
				Module:        "nuclei",
				References:    r.Info.Reference,
				Evidence: []Evidence{{
					Type:        "match",
					Description: "Nuclei match",
					Data:        r.Matched,
				}},
			})
		}
	}

	return findings, nil
}

type nucleiResult struct {
	TemplateID string     `json:"template-id"`
	Host       string     `json:"host"`
	Matched    string     `json:"matched-at"`
	Info       nucleiInfo `json:"info"`
}

type nucleiInfo struct {
	Name           string               `json:"name"`
	Severity       string               `json:"severity"`
	Description    string               `json:"description"`
	Reference      []string             `json:"reference"`
	Classification nucleiClassification `json:"classification"`
}

type nucleiClassification struct {
	CVEId     []string `json:"cve-id"`
	CWEId     []string `json:"cwe-id"`
	CVSSScore float64  `json:"cvss-score"`
}

// readJSONL reads a JSONL file and returns slice of T
func readJSONL[T any](path string) ([]T, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var results []T
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var item T
		if err := json.Unmarshal(line, &item); err != nil {
			continue
		}
		results = append(results, item)
	}

	return results, scanner.Err()
}
