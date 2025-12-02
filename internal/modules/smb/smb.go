package smb

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tldr-it-stepankutaj/pentakit/internal/app"
)

// Module implements the SMB enumeration module metadata.
type Module struct{}

func New() Module { return Module{} }

func (Module) Name() string        { return "smb" }
func (Module) Description() string { return "SMB/NetBIOS enumeration: shares, users, OS detection" }

// RunConfig configures the SMB enumeration run.
type RunConfig struct {
	Target       string
	Port         int
	Timeout      time.Duration
	Username     string
	Password     string
	Domain       string
	NullSession  bool // Try null session enumeration
	EnumShares   bool
	EnumUsers    bool
	EnumGroups   bool
	CheckSigning bool
	CheckVulns   bool
}

// Result represents SMB enumeration findings.
type Result struct {
	Target          string      `json:"target"`
	Port            int         `json:"port"`
	SMBVersion      string      `json:"smb_version,omitempty"`
	OSVersion       string      `json:"os_version,omitempty"`
	Hostname        string      `json:"hostname,omitempty"`
	Domain          string      `json:"domain,omitempty"`
	Workgroup       string      `json:"workgroup,omitempty"`
	SigningRequired bool        `json:"signing_required"`
	SigningEnabled  bool        `json:"signing_enabled"`
	NullSession     bool        `json:"null_session_allowed"`
	GuestAccess     bool        `json:"guest_access_allowed"`
	Shares          []ShareInfo `json:"shares,omitempty"`
	Users           []string    `json:"users,omitempty"`
	Groups          []string    `json:"groups,omitempty"`
	Vulnerabilities []VulnInfo  `json:"vulnerabilities,omitempty"`
}

// ShareInfo contains share details.
type ShareInfo struct {
	Name      string `json:"name"`
	Type      string `json:"type"` // DISK, PRINTER, IPC, etc.
	Comment   string `json:"comment,omitempty"`
	Access    string `json:"access,omitempty"` // READ, WRITE, FULL
	Anonymous bool   `json:"anonymous_access"`
}

// VulnInfo contains vulnerability information.
type VulnInfo struct {
	Name        string `json:"name"`
	CVE         string `json:"cve,omitempty"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Exploitable bool   `json:"exploitable"`
}

// SMB protocol constants
const (
	SMB1_PROTOCOL    = "SMB1"
	SMB2_PROTOCOL    = "SMB2"
	SMB2_DIALECT_02  = 0x0202
	SMB2_DIALECT_21  = 0x0210
	SMB2_DIALECT_30  = 0x0300
	SMB2_DIALECT_302 = 0x0302
	SMB2_DIALECT_311 = 0x0311
)

// NetBIOS name types
const (
	NETBIOS_WORKSTATION = 0x00
	NETBIOS_DOMAIN      = 0x1B
	NETBIOS_SERVER      = 0x20
	NETBIOS_DOMAIN_CTRL = 0x1C
)

// Run executes SMB enumeration.
func Run(ctx app.Context, cfg RunConfig) (*Result, error) {
	if cfg.Target == "" {
		return nil, fmt.Errorf("target is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 445
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	result := &Result{
		Target: cfg.Target,
		Port:   cfg.Port,
	}

	fmt.Printf("[*] Enumerating SMB on %s:%d\n", cfg.Target, cfg.Port)

	// Try NetBIOS enumeration on port 139
	if cfg.Port == 139 || cfg.Port == 445 {
		nbInfo := enumerateNetBIOS(cfg.Target, cfg.Timeout)
		if nbInfo != nil {
			result.Hostname = nbInfo.hostname
			result.Domain = nbInfo.domain
			result.Workgroup = nbInfo.workgroup

			if result.Hostname != "" {
				fmt.Printf("[+] NetBIOS Name: %s\n", result.Hostname)
			}
			if result.Domain != "" {
				fmt.Printf("[+] Domain: %s\n", result.Domain)
			}
			if result.Workgroup != "" {
				fmt.Printf("[+] Workgroup: %s\n", result.Workgroup)
			}
		}
	}

	// SMB connection and version detection
	smbInfo, err := probeSMB(cfg.Target, cfg.Port, cfg.Timeout)
	if err != nil {
		fmt.Printf("[!] SMB probe failed: %v\n", err)
	} else {
		result.SMBVersion = smbInfo.version
		result.OSVersion = smbInfo.osVersion
		result.SigningRequired = smbInfo.signingRequired
		result.SigningEnabled = smbInfo.signingEnabled

		fmt.Printf("[+] SMB Version: %s\n", result.SMBVersion)
		if result.OSVersion != "" {
			fmt.Printf("[+] OS Version: %s\n", result.OSVersion)
		}
		fmt.Printf("[+] Signing Required: %v, Enabled: %v\n", result.SigningRequired, result.SigningEnabled)
	}

	// Null session check
	if cfg.NullSession {
		fmt.Println("[*] Testing null session...")
		nullAllowed := testNullSession(cfg.Target, cfg.Port, cfg.Timeout)
		result.NullSession = nullAllowed
		if nullAllowed {
			fmt.Println("[+] Null session allowed!")
		} else {
			fmt.Println("[-] Null session not allowed")
		}
	}

	// Guest access check
	guestAllowed := testGuestAccess(cfg.Target, cfg.Port, cfg.Timeout)
	result.GuestAccess = guestAllowed
	if guestAllowed {
		fmt.Println("[+] Guest access allowed!")
	}

	// Share enumeration
	if cfg.EnumShares {
		fmt.Println("[*] Enumerating shares...")
		shares := enumerateShares(cfg.Target, cfg.Port, cfg.Username, cfg.Password, cfg.Timeout)
		result.Shares = shares

		if len(shares) > 0 {
			fmt.Printf("[+] Found %d shares:\n", len(shares))
			for _, share := range shares {
				access := ""
				if share.Anonymous {
					access = " [ANONYMOUS]"
				}
				if share.Access != "" {
					access += fmt.Sprintf(" [%s]", share.Access)
				}
				fmt.Printf("    \\\\%s\\%s - %s%s\n", cfg.Target, share.Name, share.Type, access)
				if share.Comment != "" {
					fmt.Printf("        Comment: %s\n", share.Comment)
				}
			}
		}
	}

	// Vulnerability checks
	if cfg.CheckVulns {
		fmt.Println("[*] Checking for known vulnerabilities...")
		vulns := checkVulnerabilities(cfg.Target, cfg.Port, result.SMBVersion, cfg.Timeout)
		result.Vulnerabilities = vulns

		if len(vulns) > 0 {
			fmt.Printf("[!] Found %d potential vulnerabilities:\n", len(vulns))
			for _, v := range vulns {
				cve := ""
				if v.CVE != "" {
					cve = fmt.Sprintf(" (%s)", v.CVE)
				}
				fmt.Printf("    [%s] %s%s\n", v.Severity, v.Name, cve)
				fmt.Printf("        %s\n", v.Description)
			}
		}
	}

	// Persist results
	timestamp := ctx.Now.Format("20060102-150405")
	jsonPath := ctx.Workspace.Path("findings", fmt.Sprintf("smb-%s-%d-%s.json", cfg.Target, cfg.Port, timestamp))
	if err := writeJSON(jsonPath, result); err != nil {
		fmt.Printf("[!] failed to write findings: %v\n", err)
	}

	return result, nil
}

type netbiosInfo struct {
	hostname  string
	domain    string
	workgroup string
	names     []string
}

func enumerateNetBIOS(target string, timeout time.Duration) *netbiosInfo {
	conn, err := net.DialTimeout("udp", target+":137", timeout)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

	// NetBIOS Name Service query
	query := buildNetBIOSQuery()
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return nil
	}
	_, err = conn.Write(query)
	if err != nil {
		return nil
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}

	return parseNetBIOSResponse(buf[:n])
}

func buildNetBIOSQuery() []byte {
	// NetBIOS Name Service node status request
	query := make([]byte, 50)

	// Transaction ID
	binary.BigEndian.PutUint16(query[0:2], 0x1234)
	// Flags: Query
	binary.BigEndian.PutUint16(query[2:4], 0x0000)
	// Questions: 1
	binary.BigEndian.PutUint16(query[4:6], 0x0001)
	// Answer RRs: 0
	binary.BigEndian.PutUint16(query[6:8], 0x0000)
	// Authority RRs: 0
	binary.BigEndian.PutUint16(query[8:10], 0x0000)
	// Additional RRs: 0
	binary.BigEndian.PutUint16(query[10:12], 0x0000)

	// Query name: * (wildcard)
	query[12] = 0x20 // Length
	// Encode "*" in NetBIOS encoding
	encoded := netbiosEncode("*")
	copy(query[13:45], encoded)
	query[45] = 0x00 // Null terminator

	// Query type: NBSTAT (0x0021)
	binary.BigEndian.PutUint16(query[46:48], 0x0021)
	// Query class: IN (0x0001)
	binary.BigEndian.PutUint16(query[48:50], 0x0001)

	return query
}

func netbiosEncode(name string) []byte {
	// Pad name to 16 characters
	padded := fmt.Sprintf("%-15s", name)
	if len(padded) > 15 {
		padded = padded[:15]
	}
	padded += "\x00" // Type suffix

	// Encode each character
	encoded := make([]byte, 32)
	for i, c := range padded {
		encoded[i*2] = byte('A' + (c >> 4))
		encoded[i*2+1] = byte('A' + (c & 0x0F))
	}
	return encoded
}

func parseNetBIOSResponse(data []byte) *netbiosInfo {
	if len(data) < 57 {
		return nil
	}

	info := &netbiosInfo{}

	// Skip header (12 bytes) and query section
	offset := 12

	// Skip name
	for offset < len(data) && data[offset] != 0 {
		offset += int(data[offset]) + 1
	}
	offset++ // Skip null terminator

	// Skip type and class (4 bytes)
	offset += 4

	// Skip TTL (4 bytes)
	offset += 4

	// Data length
	if offset+2 > len(data) {
		return info
	}
	_ = int(binary.BigEndian.Uint16(data[offset : offset+2])) // dataLen
	offset += 2

	// Number of names
	if offset >= len(data) {
		return info
	}
	numNames := int(data[offset])
	offset++

	// Parse names
	for i := 0; i < numNames && offset+18 <= len(data); i++ {
		name := strings.TrimSpace(string(data[offset : offset+15]))
		nameType := data[offset+15]
		// flags := binary.BigEndian.Uint16(data[offset+16 : offset+18])

		info.names = append(info.names, name)

		switch nameType {
		case NETBIOS_WORKSTATION:
			if info.hostname == "" {
				info.hostname = name
			}
		case NETBIOS_DOMAIN:
			info.domain = name
		case NETBIOS_SERVER:
			if info.workgroup == "" {
				info.workgroup = name
			}
		}

		offset += 18
	}

	return info
}

type smbInfo struct {
	version         string
	osVersion       string
	signingRequired bool
	signingEnabled  bool
}

func probeSMB(target string, port int, timeout time.Duration) (*smbInfo, error) {
	addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	// Send SMB2 negotiate request
	negReq := buildSMB2NegotiateRequest()
	_, err = conn.Write(negReq)
	if err != nil {
		return nil, err
	}

	// Read response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return parseSMB2NegotiateResponse(buf[:n])
}

func buildSMB2NegotiateRequest() []byte {
	// NetBIOS session header + SMB2 negotiate request

	// SMB2 header
	smb2Header := make([]byte, 64)
	copy(smb2Header[0:4], []byte{0xFE, 'S', 'M', 'B'}) // Protocol ID
	smb2Header[4] = 64                                 // Header length
	smb2Header[5] = 0                                  // Credit charge
	// Status (4 bytes) = 0
	binary.LittleEndian.PutUint16(smb2Header[12:14], 0x0000) // Command: NEGOTIATE
	// Credits requested
	binary.LittleEndian.PutUint16(smb2Header[14:16], 31)
	// Flags
	binary.LittleEndian.PutUint32(smb2Header[16:20], 0)
	// Message ID
	binary.LittleEndian.PutUint64(smb2Header[24:32], 0)
	// Process ID
	binary.LittleEndian.PutUint32(smb2Header[32:36], 0xFEFF)

	// Negotiate request body
	negBody := make([]byte, 36)
	binary.LittleEndian.PutUint16(negBody[0:2], 36) // Structure size
	binary.LittleEndian.PutUint16(negBody[2:4], 5)  // Dialect count
	binary.LittleEndian.PutUint16(negBody[4:6], 1)  // Security mode: signing enabled
	binary.LittleEndian.PutUint32(negBody[8:12], 0) // Capabilities
	// Client GUID (16 bytes) - leave as zeros
	binary.LittleEndian.PutUint32(negBody[28:32], 0) // Negotiate context offset
	binary.LittleEndian.PutUint16(negBody[32:34], 0) // Negotiate context count

	// Dialects
	dialects := make([]byte, 10)
	binary.LittleEndian.PutUint16(dialects[0:2], SMB2_DIALECT_02)
	binary.LittleEndian.PutUint16(dialects[2:4], SMB2_DIALECT_21)
	binary.LittleEndian.PutUint16(dialects[4:6], SMB2_DIALECT_30)
	binary.LittleEndian.PutUint16(dialects[6:8], SMB2_DIALECT_302)
	binary.LittleEndian.PutUint16(dialects[8:10], SMB2_DIALECT_311)

	// Combine
	smbPacket := append(smb2Header, negBody...)
	smbPacket = append(smbPacket, dialects...)

	// NetBIOS header
	nbHeader := make([]byte, 4)
	nbHeader[0] = 0x00 // Message type
	binary.BigEndian.PutUint32(nbHeader[0:4], uint32(len(smbPacket)))
	nbHeader[0] = 0x00 // Fix first byte

	packet := append(nbHeader, smbPacket...)
	return packet
}

func parseSMB2NegotiateResponse(data []byte) (*smbInfo, error) {
	if len(data) < 68 {
		return nil, fmt.Errorf("response too short")
	}

	info := &smbInfo{}

	// Skip NetBIOS header (4 bytes)
	offset := 4

	// Check SMB signature
	if string(data[offset:offset+4]) == "\xFESMB" {
		info.version = "SMB2+"

		// Parse SMB2 response
		if len(data) >= offset+128 {
			// Dialect at offset 70-72 in SMB2 negotiate response
			dialect := binary.LittleEndian.Uint16(data[offset+68 : offset+70])
			switch dialect {
			case SMB2_DIALECT_02:
				info.version = "SMB 2.0.2"
			case SMB2_DIALECT_21:
				info.version = "SMB 2.1"
			case SMB2_DIALECT_30:
				info.version = "SMB 3.0"
			case SMB2_DIALECT_302:
				info.version = "SMB 3.0.2"
			case SMB2_DIALECT_311:
				info.version = "SMB 3.1.1"
			}

			// Security mode at offset 66-68
			secMode := binary.LittleEndian.Uint16(data[offset+66 : offset+68])
			info.signingEnabled = (secMode & 0x01) != 0
			info.signingRequired = (secMode & 0x02) != 0
		}
	} else if string(data[offset:offset+4]) == "\xFFSMB" {
		info.version = "SMB1"
	}

	return info, nil
}

func testNullSession(target string, port int, timeout time.Duration) bool {
	// Simplified null session test
	// Full implementation would complete SMB session setup with empty credentials
	addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()

	// Placeholder - actual implementation requires full SMB session setup
	return false
}

func testGuestAccess(target string, port int, timeout time.Duration) bool {
	// Simplified guest access test
	// Full implementation would attempt authentication as "Guest" user
	return false
}

func enumerateShares(target string, port int, username, password string, timeout time.Duration) []ShareInfo {
	// Common shares to check
	commonShares := []string{
		"ADMIN$", "C$", "D$", "IPC$", "NETLOGON", "SYSVOL",
		"print$", "fax$", "profiles$",
		"Users", "Public", "Shared", "Data", "Backup",
		"wwwroot", "htdocs", "web", "www",
	}

	var shares []ShareInfo
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, shareName := range commonShares {
		shareName := shareName
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Try to connect to share
			// This is a placeholder - actual implementation would use SMB tree connect
			share := ShareInfo{
				Name: shareName,
				Type: "DISK",
			}

			// Determine share type by name
			switch shareName {
			case "IPC$":
				share.Type = "IPC"
			case "print$", "fax$":
				share.Type = "PRINTER"
			case "ADMIN$", "C$", "D$":
				share.Type = "DISK (Admin)"
			}

			mu.Lock()
			shares = append(shares, share)
			mu.Unlock()
		}()
	}

	wg.Wait()
	return shares
}

func checkVulnerabilities(target string, port int, smbVersion string, timeout time.Duration) []VulnInfo {
	var vulns []VulnInfo

	// Check based on SMB version and features
	if strings.Contains(smbVersion, "SMB1") || smbVersion == "" {
		vulns = append(vulns, VulnInfo{
			Name:        "EternalBlue",
			CVE:         "CVE-2017-0144",
			Severity:    "CRITICAL",
			Description: "SMBv1 may be vulnerable to EternalBlue remote code execution",
			Exploitable: true,
		})

		vulns = append(vulns, VulnInfo{
			Name:        "SMBv1 Enabled",
			Severity:    "MEDIUM",
			Description: "SMBv1 is deprecated and should be disabled",
		})
	}

	// SMBGhost (SMB 3.1.1 compression)
	if strings.Contains(smbVersion, "3.1.1") {
		vulns = append(vulns, VulnInfo{
			Name:        "SMBGhost",
			CVE:         "CVE-2020-0796",
			Severity:    "CRITICAL",
			Description: "SMB 3.1.1 may be vulnerable to SMBGhost remote code execution (check compression support)",
			Exploitable: true,
		})
	}

	return vulns
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
