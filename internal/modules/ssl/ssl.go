package ssl

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tldr-it-stepankutaj/pentakit/internal/app"
)

// Module implements the SSL/TLS analysis module metadata.
type Module struct{}

func New() Module { return Module{} }

func (Module) Name() string        { return "ssl" }
func (Module) Description() string { return "SSL/TLS analysis: certificates, ciphers, vulnerabilities" }

// RunConfig configures the SSL/TLS analysis run.
type RunConfig struct {
	Target   string
	Port     int
	Timeout  time.Duration
	CheckAll bool // Check all TLS versions
}

// Result represents SSL/TLS analysis findings.
type Result struct {
	Host              string          `json:"host"`
	Port              int             `json:"port"`
	TLSVersion        string          `json:"tls_version"`
	CipherSuite       string          `json:"cipher_suite"`
	Certificate       *CertInfo       `json:"certificate,omitempty"`
	SupportedVersions []string        `json:"supported_versions,omitempty"`
	SupportedCiphers  []string        `json:"supported_ciphers,omitempty"`
	Vulnerabilities   []Vulnerability `json:"vulnerabilities,omitempty"`
	Warnings          []string        `json:"warnings,omitempty"`
}

// CertInfo contains certificate details.
type CertInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	IPAddresses        []string  `json:"ip_addresses,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	PublicKeyBits      int       `json:"public_key_bits"`
	IsCA               bool      `json:"is_ca"`
	IsSelfSigned       bool      `json:"is_self_signed"`
	DaysUntilExpiry    int       `json:"days_until_expiry"`
}

// Vulnerability represents a detected SSL/TLS vulnerability.
type Vulnerability struct {
	Name        string `json:"name"`
	Severity    string `json:"severity"` // critical, high, medium, low, info
	Description string `json:"description"`
	CVE         string `json:"cve,omitempty"`
}

// TLS version constants for testing.
// Note: SSL 3.0 (0x0300) is deprecated and removed from Go's crypto/tls.
// We still test for it to detect vulnerable servers.
var tlsVersions = []struct {
	Name    string
	Version uint16
}{
	{"TLS 1.3", tls.VersionTLS13},
	{"TLS 1.2", tls.VersionTLS12},
	{"TLS 1.1", tls.VersionTLS11},
	{"TLS 1.0", tls.VersionTLS10},
	{"SSL 3.0", 0x0300}, // Deprecated constant, using raw value
}

// Weak cipher suites.
var weakCiphers = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:            "RC4-SHA (weak)",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:       "3DES-CBC-SHA (weak)",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:        "AES128-CBC-SHA (no forward secrecy)",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:        "AES256-CBC-SHA (no forward secrecy)",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:     "AES128-CBC-SHA256 (no forward secrecy)",
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:     "AES128-GCM-SHA256 (no forward secrecy)",
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:     "AES256-GCM-SHA384 (no forward secrecy)",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:      "ECDHE-RC4-SHA (weak RC4)",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: "ECDHE-3DES-CBC-SHA (weak 3DES)",
}

// Run executes SSL/TLS analysis.
func Run(ctx app.Context, cfg RunConfig) (*Result, error) {
	if cfg.Target == "" {
		return nil, fmt.Errorf("target is required")
	}
	if cfg.Port <= 0 {
		cfg.Port = 443
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	addr := fmt.Sprintf("%s:%d", cfg.Target, cfg.Port)
	fmt.Printf("[*] Analyzing SSL/TLS on %s\n", addr)

	result := &Result{
		Host: cfg.Target,
		Port: cfg.Port,
	}

	// Get certificate and connection info
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}

	dialer := &net.Dialer{Timeout: cfg.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer func() { _ = conn.Close() }()

	state := conn.ConnectionState()
	result.TLSVersion = tlsVersionName(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	fmt.Printf("[+] Connected with %s using %s\n", result.TLSVersion, result.CipherSuite)

	// Analyze certificate
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Certificate = analyzeCertificate(cert)

		fmt.Printf("\n[*] Certificate Information:\n")
		fmt.Printf("    Subject: %s\n", result.Certificate.Subject)
		fmt.Printf("    Issuer: %s\n", result.Certificate.Issuer)
		fmt.Printf("    Valid: %s to %s\n",
			result.Certificate.NotBefore.Format("2006-01-02"),
			result.Certificate.NotAfter.Format("2006-01-02"))
		fmt.Printf("    Days until expiry: %d\n", result.Certificate.DaysUntilExpiry)

		if len(result.Certificate.DNSNames) > 0 {
			fmt.Printf("    DNS Names: %s\n", strings.Join(result.Certificate.DNSNames, ", "))
		}

		fmt.Printf("    Signature: %s\n", result.Certificate.SignatureAlgorithm)
		fmt.Printf("    Public Key: %s (%d bits)\n",
			result.Certificate.PublicKeyAlgorithm, result.Certificate.PublicKeyBits)

		if result.Certificate.IsSelfSigned {
			fmt.Printf("    [!] Self-signed certificate\n")
		}
	}

	// Check supported TLS versions
	if cfg.CheckAll {
		fmt.Printf("\n[*] Checking supported TLS versions...\n")
		result.SupportedVersions = checkSupportedVersions(cfg.Target, cfg.Port, cfg.Timeout)
		for _, v := range result.SupportedVersions {
			fmt.Printf("    [+] %s supported\n", v)
		}

		// Check for weak ciphers
		fmt.Printf("\n[*] Checking cipher suites...\n")
		result.SupportedCiphers = checkCipherSuites(cfg.Target, cfg.Port, cfg.Timeout)
	}

	// Identify vulnerabilities
	result.Vulnerabilities = identifyVulnerabilities(result, state)
	result.Warnings = generateWarnings(result)

	if len(result.Vulnerabilities) > 0 {
		fmt.Printf("\n[!] Vulnerabilities Found:\n")
		for _, v := range result.Vulnerabilities {
			cve := ""
			if v.CVE != "" {
				cve = fmt.Sprintf(" (%s)", v.CVE)
			}
			fmt.Printf("    [%s] %s%s\n", strings.ToUpper(v.Severity), v.Name, cve)
			fmt.Printf("        %s\n", v.Description)
		}
	}

	if len(result.Warnings) > 0 {
		fmt.Printf("\n[*] Warnings:\n")
		for _, w := range result.Warnings {
			fmt.Printf("    - %s\n", w)
		}
	}

	// Persist results
	timestamp := ctx.Now.Format("20060102-150405")
	jsonPath := ctx.Workspace.Path("findings", fmt.Sprintf("ssl-%s-%d-%s.json", cfg.Target, cfg.Port, timestamp))
	if err := writeJSON(jsonPath, result); err != nil {
		fmt.Printf("[!] failed to write findings: %v\n", err)
	}

	return result, nil
}

func analyzeCertificate(cert *x509.Certificate) *CertInfo {
	info := &CertInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		DNSNames:           cert.DNSNames,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		IsCA:               cert.IsCA,
		IsSelfSigned:       cert.Subject.String() == cert.Issuer.String(),
		DaysUntilExpiry:    int(time.Until(cert.NotAfter).Hours() / 24),
	}

	// Get IP addresses
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}

	// Get public key bits
	switch pub := cert.PublicKey.(type) {
	case interface{ Size() int }:
		info.PublicKeyBits = pub.Size() * 8
	default:
		// Estimate based on algorithm
		switch cert.PublicKeyAlgorithm {
		case x509.RSA:
			info.PublicKeyBits = 2048 // Default assumption
		case x509.ECDSA:
			info.PublicKeyBits = 256 // Default assumption
		}
	}

	return info
}

func checkSupportedVersions(host string, port int, timeout time.Duration) []string {
	var supported []string
	addr := fmt.Sprintf("%s:%d", host, port)

	for _, v := range tlsVersions {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         v.Version,
			MaxVersion:         v.Version,
		}

		dialer := &net.Dialer{Timeout: timeout}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if err == nil {
			supported = append(supported, v.Name)
			_ = conn.Close()
		}
	}

	return supported
}

func checkCipherSuites(host string, port int, timeout time.Duration) []string {
	var supported []string
	addr := fmt.Sprintf("%s:%d", host, port)

	// Get all cipher suites
	cipherSuites := tls.CipherSuites()
	insecureCipherSuites := tls.InsecureCipherSuites()

	allSuites := make([]uint16, 0)
	for _, cs := range cipherSuites {
		allSuites = append(allSuites, cs.ID)
	}
	for _, cs := range insecureCipherSuites {
		allSuites = append(allSuites, cs.ID)
	}

	// Test each cipher suite
	for _, suiteID := range allSuites {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			CipherSuites:       []uint16{suiteID},
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS12, // TLS 1.3 manages its own cipher suites
		}

		dialer := &net.Dialer{Timeout: timeout}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if err == nil {
			name := tls.CipherSuiteName(suiteID)
			supported = append(supported, name)

			if weakness, ok := weakCiphers[suiteID]; ok {
				fmt.Printf("    [!] %s - %s\n", name, weakness)
			} else {
				fmt.Printf("    [+] %s\n", name)
			}

			_ = conn.Close()
		}
	}

	return supported
}

func identifyVulnerabilities(result *Result, state tls.ConnectionState) []Vulnerability {
	var vulns []Vulnerability

	// Check for deprecated TLS versions
	for _, v := range result.SupportedVersions {
		switch v {
		case "SSL 3.0":
			vulns = append(vulns, Vulnerability{
				Name:        "POODLE",
				Severity:    "high",
				Description: "SSL 3.0 is vulnerable to POODLE attack",
				CVE:         "CVE-2014-3566",
			})
		case "TLS 1.0":
			vulns = append(vulns, Vulnerability{
				Name:        "BEAST",
				Severity:    "medium",
				Description: "TLS 1.0 is vulnerable to BEAST attack and is deprecated",
				CVE:         "CVE-2011-3389",
			})
		case "TLS 1.1":
			vulns = append(vulns, Vulnerability{
				Name:        "Deprecated Protocol",
				Severity:    "low",
				Description: "TLS 1.1 is deprecated and should not be used",
			})
		}
	}

	// Check for weak ciphers in use
	if _, ok := weakCiphers[state.CipherSuite]; ok {
		vulns = append(vulns, Vulnerability{
			Name:        "Weak Cipher Suite",
			Severity:    "medium",
			Description: fmt.Sprintf("Server negotiated weak cipher: %s", tls.CipherSuiteName(state.CipherSuite)),
		})
	}

	// Check certificate issues
	if result.Certificate != nil {
		// Expired certificate
		if result.Certificate.DaysUntilExpiry < 0 {
			vulns = append(vulns, Vulnerability{
				Name:        "Expired Certificate",
				Severity:    "critical",
				Description: "The SSL certificate has expired",
			})
		} else if result.Certificate.DaysUntilExpiry < 30 {
			vulns = append(vulns, Vulnerability{
				Name:        "Certificate Expiring Soon",
				Severity:    "medium",
				Description: fmt.Sprintf("Certificate expires in %d days", result.Certificate.DaysUntilExpiry),
			})
		}

		// Self-signed certificate
		if result.Certificate.IsSelfSigned {
			vulns = append(vulns, Vulnerability{
				Name:        "Self-Signed Certificate",
				Severity:    "medium",
				Description: "Server uses a self-signed certificate",
			})
		}

		// Weak signature algorithm
		sigAlgo := strings.ToLower(result.Certificate.SignatureAlgorithm)
		if strings.Contains(sigAlgo, "md5") {
			vulns = append(vulns, Vulnerability{
				Name:        "Weak Signature Algorithm",
				Severity:    "high",
				Description: "Certificate uses MD5 signature algorithm",
			})
		} else if strings.Contains(sigAlgo, "sha1") {
			vulns = append(vulns, Vulnerability{
				Name:        "Weak Signature Algorithm",
				Severity:    "medium",
				Description: "Certificate uses SHA-1 signature algorithm (deprecated)",
			})
		}

		// Weak key size
		if result.Certificate.PublicKeyAlgorithm == "RSA" && result.Certificate.PublicKeyBits < 2048 {
			vulns = append(vulns, Vulnerability{
				Name:        "Weak Key Size",
				Severity:    "high",
				Description: fmt.Sprintf("RSA key size is %d bits (minimum 2048 recommended)", result.Certificate.PublicKeyBits),
			})
		}
	}

	return vulns
}

func generateWarnings(result *Result) []string {
	var warnings []string

	// Check if TLS 1.3 is not supported
	tls13Supported := false
	for _, v := range result.SupportedVersions {
		if v == "TLS 1.3" {
			tls13Supported = true
			break
		}
	}
	if !tls13Supported && len(result.SupportedVersions) > 0 {
		warnings = append(warnings, "TLS 1.3 is not supported - consider enabling it for better security")
	}

	// Check certificate validity period
	if result.Certificate != nil {
		if result.Certificate.DaysUntilExpiry > 0 && result.Certificate.DaysUntilExpiry < 90 {
			warnings = append(warnings, fmt.Sprintf("Certificate expires in %d days - consider renewal", result.Certificate.DaysUntilExpiry))
		}

		// Check for wildcard certificate
		for _, name := range result.Certificate.DNSNames {
			if strings.HasPrefix(name, "*") {
				warnings = append(warnings, "Wildcard certificate in use - ensure proper scope management")
				break
			}
		}
	}

	return warnings
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case 0x0300: // SSL 3.0 - deprecated constant
		return "SSL 3.0"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

func writeJSON(path string, result *Result) error {
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
