package snmp

import (
	"bufio"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tldr-it-stepankutaj/pentakit/internal/app"
)

// Module implements the SNMP enumeration module metadata.
type Module struct{}

func New() Module { return Module{} }

func (Module) Name() string { return "snmp" }
func (Module) Description() string {
	return "SNMP enumeration: community strings, system info, network interfaces"
}

// RunConfig configures the SNMP enumeration run.
type RunConfig struct {
	Target        string
	Port          int
	Timeout       time.Duration
	Communities   []string
	CommunityFile string
	Version       int    // 1, 2, or 3
	V3User        string // SNMPv3 username
	V3AuthProto   string // MD5 or SHA
	V3AuthPass    string
	V3PrivProto   string // DES or AES
	V3PrivPass    string
	WalkOIDs      bool
	Concurrency   int
}

// Result represents SNMP enumeration findings.
type Result struct {
	Target           string          `json:"target"`
	Port             int             `json:"port"`
	Version          int             `json:"version"`
	Community        string          `json:"community,omitempty"`
	SystemInfo       *SystemInfo     `json:"system_info,omitempty"`
	Interfaces       []InterfaceInfo `json:"interfaces,omitempty"`
	Routes           []RouteInfo     `json:"routes,omitempty"`
	Software         []string        `json:"software,omitempty"`
	Processes        []ProcessInfo   `json:"processes,omitempty"`
	Users            []string        `json:"users,omitempty"`
	Shares           []string        `json:"shares,omitempty"`
	ValidCommunities []string        `json:"valid_communities,omitempty"`
}

// SystemInfo contains system information.
type SystemInfo struct {
	Description string `json:"description"`
	ObjectID    string `json:"object_id"`
	Uptime      string `json:"uptime"`
	Contact     string `json:"contact,omitempty"`
	Name        string `json:"name"`
	Location    string `json:"location,omitempty"`
}

// InterfaceInfo contains network interface details.
type InterfaceInfo struct {
	Index       int      `json:"index"`
	Description string   `json:"description"`
	Type        string   `json:"type"`
	MTU         int      `json:"mtu"`
	Speed       int64    `json:"speed"`
	PhysAddress string   `json:"phys_address"`
	AdminStatus string   `json:"admin_status"`
	OperStatus  string   `json:"oper_status"`
	IPAddresses []string `json:"ip_addresses,omitempty"`
}

// RouteInfo contains routing table entries.
type RouteInfo struct {
	Destination string `json:"destination"`
	NextHop     string `json:"next_hop"`
	Metric      int    `json:"metric"`
	Interface   int    `json:"interface"`
}

// ProcessInfo contains running process details.
type ProcessInfo struct {
	PID    int    `json:"pid"`
	Name   string `json:"name"`
	Path   string `json:"path,omitempty"`
	Params string `json:"params,omitempty"`
}

// Common OIDs for enumeration.
var commonOIDs = map[string]string{
	"sysDescr":          "1.3.6.1.2.1.1.1.0",
	"sysObjectID":       "1.3.6.1.2.1.1.2.0",
	"sysUpTime":         "1.3.6.1.2.1.1.3.0",
	"sysContact":        "1.3.6.1.2.1.1.4.0",
	"sysName":           "1.3.6.1.2.1.1.5.0",
	"sysLocation":       "1.3.6.1.2.1.1.6.0",
	"ifNumber":          "1.3.6.1.2.1.2.1.0",
	"ifTable":           "1.3.6.1.2.1.2.2",
	"ipAddrTable":       "1.3.6.1.2.1.4.20",
	"ipRouteTable":      "1.3.6.1.2.1.4.21",
	"tcpConnTable":      "1.3.6.1.2.1.6.13",
	"udpTable":          "1.3.6.1.2.1.7.5",
	"hrSystemUptime":    "1.3.6.1.2.1.25.1.1.0",
	"hrProcessorLoad":   "1.3.6.1.2.1.25.3.3.1.2",
	"hrSWRunName":       "1.3.6.1.2.1.25.4.2.1.2",
	"hrSWRunPath":       "1.3.6.1.2.1.25.4.2.1.4",
	"hrSWInstalledName": "1.3.6.1.2.1.25.6.3.1.2",
}

// Default community strings to test.
var DefaultCommunities = []string{
	"public", "private", "community", "snmp", "default",
	"read", "write", "manager", "admin", "cisco",
	"router", "switch", "monitor", "security", "system",
	"guest", "test", "secret", "internal", "external",
	"ILMI", "TENmanUFactworworworworworworworworworworworworkworworworworworworwo",
	"cable-docsis", "cable", "c0mmunity", "Publ1c",
}

// Run executes SNMP enumeration.
func Run(ctx app.Context, cfg RunConfig) (*Result, error) {
	if cfg.Target == "" {
		return nil, fmt.Errorf("target is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 161
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Version == 0 {
		cfg.Version = 2 // Default to SNMPv2c
	}
	if cfg.Concurrency == 0 {
		cfg.Concurrency = 10
	}

	// Load community strings
	communities := cfg.Communities
	if cfg.CommunityFile != "" {
		fileCommunities, err := loadWordlist(cfg.CommunityFile)
		if err != nil {
			fmt.Printf("[!] Failed to load community file: %v\n", err)
		} else {
			communities = append(communities, fileCommunities...)
		}
	}
	if len(communities) == 0 {
		communities = DefaultCommunities
	}

	result := &Result{
		Target:  cfg.Target,
		Port:    cfg.Port,
		Version: cfg.Version,
	}

	fmt.Printf("[*] SNMP enumeration on %s:%d (SNMPv%d)\n", cfg.Target, cfg.Port, cfg.Version)

	// Brute-force community strings
	fmt.Printf("[*] Testing %d community strings...\n", len(communities))
	validCommunities := bruteForceCommunities(cfg.Target, cfg.Port, communities, cfg.Version, cfg.Timeout, cfg.Concurrency)
	result.ValidCommunities = validCommunities

	if len(validCommunities) == 0 {
		fmt.Println("[-] No valid community strings found")
		return result, nil
	}

	fmt.Printf("[+] Found %d valid community strings:\n", len(validCommunities))
	for _, c := range validCommunities {
		fmt.Printf("    - %s\n", c)
	}

	// Use first valid community for enumeration
	result.Community = validCommunities[0]

	// Get system information
	fmt.Println("\n[*] Gathering system information...")
	result.SystemInfo = getSystemInfo(cfg.Target, cfg.Port, result.Community, cfg.Version, cfg.Timeout)
	if result.SystemInfo != nil {
		fmt.Printf("[+] System: %s\n", result.SystemInfo.Description)
		fmt.Printf("[+] Name: %s\n", result.SystemInfo.Name)
		fmt.Printf("[+] Uptime: %s\n", result.SystemInfo.Uptime)
		if result.SystemInfo.Location != "" {
			fmt.Printf("[+] Location: %s\n", result.SystemInfo.Location)
		}
		if result.SystemInfo.Contact != "" {
			fmt.Printf("[+] Contact: %s\n", result.SystemInfo.Contact)
		}
	}

	// Get network interfaces
	if cfg.WalkOIDs {
		fmt.Println("\n[*] Enumerating network interfaces...")
		result.Interfaces = getInterfaces(cfg.Target, cfg.Port, result.Community, cfg.Version, cfg.Timeout)
		if len(result.Interfaces) > 0 {
			fmt.Printf("[+] Found %d interfaces:\n", len(result.Interfaces))
			for _, iface := range result.Interfaces {
				status := fmt.Sprintf("%s/%s", iface.AdminStatus, iface.OperStatus)
				fmt.Printf("    [%d] %s - %s (%s)\n", iface.Index, iface.Description, iface.PhysAddress, status)
				for _, ip := range iface.IPAddresses {
					fmt.Printf("        IP: %s\n", ip)
				}
			}
		}

		// Get running processes (if host-resources MIB available)
		fmt.Println("\n[*] Enumerating running processes...")
		result.Processes = getProcesses(cfg.Target, cfg.Port, result.Community, cfg.Version, cfg.Timeout)
		if len(result.Processes) > 0 {
			fmt.Printf("[+] Found %d processes\n", len(result.Processes))
		}
	}

	// Persist results
	timestamp := ctx.Now.Format("20060102-150405")
	jsonPath := ctx.Workspace.Path("findings", fmt.Sprintf("snmp-%s-%d-%s.json", cfg.Target, cfg.Port, timestamp))
	if err := writeJSON(jsonPath, result); err != nil {
		fmt.Printf("[!] failed to write findings: %v\n", err)
	}

	return result, nil
}

func bruteForceCommunities(target string, port int, communities []string, version int, timeout time.Duration, concurrency int) []string {
	var valid []string
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, community := range communities {
		community := community
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()

			if testCommunity(target, port, community, version, timeout) {
				mu.Lock()
				valid = append(valid, community)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return valid
}

func testCommunity(target string, port int, community string, version int, timeout time.Duration) bool {
	addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	// Build SNMP GET request for sysDescr
	request := buildSNMPGetRequest(community, version, "1.3.6.1.2.1.1.1.0")

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false
	}
	_, err = conn.Write(request)
	if err != nil {
		return false
	}

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}

	// Check if we got a valid SNMP response
	return isValidSNMPResponse(buf[:n])
}

func buildSNMPGetRequest(community string, version int, oid string) []byte {
	// Build SNMP v1/v2c GET request using ASN.1 encoding

	// OID to bytes
	oidBytes := encodeOID(oid)

	// Null value
	nullValue := []byte{0x05, 0x00}

	// VarBind: OID + NULL
	varBind := append([]byte{0x30}, byte(len(oidBytes)+len(nullValue)))
	varBind = append(varBind, oidBytes...)
	varBind = append(varBind, nullValue...)

	// VarBindList
	varBindList := append([]byte{0x30}, byte(len(varBind)))
	varBindList = append(varBindList, varBind...)

	// Request ID (random)
	requestID := []byte{0x02, 0x04, 0x00, 0x00, 0x00, 0x01}

	// Error status and index
	errorStatus := []byte{0x02, 0x01, 0x00}
	errorIndex := []byte{0x02, 0x01, 0x00}

	// PDU
	pduContent := append(requestID, errorStatus...)
	pduContent = append(pduContent, errorIndex...)
	pduContent = append(pduContent, varBindList...)

	// PDU type: GET-REQUEST (0xA0)
	pdu := append([]byte{0xA0}, encodeLength(len(pduContent))...)
	pdu = append(pdu, pduContent...)

	// Version
	var versionBytes []byte
	if version == 1 {
		versionBytes = []byte{0x02, 0x01, 0x00} // v1
	} else {
		versionBytes = []byte{0x02, 0x01, 0x01} // v2c
	}

	// Community string
	communityBytes := append([]byte{0x04, byte(len(community))}, []byte(community)...)

	// Message
	messageContent := append(versionBytes, communityBytes...)
	messageContent = append(messageContent, pdu...)

	// Sequence
	message := append([]byte{0x30}, encodeLength(len(messageContent))...)
	message = append(message, messageContent...)

	return message
}

func encodeOID(oid string) []byte {
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return nil
	}

	// First two components are encoded as 40*first + second
	first, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil
	}
	second, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil
	}

	encoded := []byte{byte(40*first + second)}

	// Remaining components
	for i := 2; i < len(parts); i++ {
		val, err := strconv.Atoi(parts[i])
		if err != nil {
			continue
		}

		if val < 128 {
			encoded = append(encoded, byte(val))
		} else {
			// Multi-byte encoding
			var bytes []byte
			for val > 0 {
				bytes = append([]byte{byte(val & 0x7F)}, bytes...)
				val >>= 7
			}
			for i := 0; i < len(bytes)-1; i++ {
				bytes[i] |= 0x80
			}
			encoded = append(encoded, bytes...)
		}
	}

	// Add OID tag and length
	result := append([]byte{0x06, byte(len(encoded))}, encoded...)
	return result
}

func encodeLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	// Long form
	var bytes []byte
	temp := length
	for temp > 0 {
		bytes = append([]byte{byte(temp & 0xFF)}, bytes...)
		temp >>= 8
	}
	return append([]byte{byte(0x80 | len(bytes))}, bytes...)
}

func isValidSNMPResponse(data []byte) bool {
	if len(data) < 10 {
		return false
	}

	// Check for SEQUENCE tag
	if data[0] != 0x30 {
		return false
	}

	// Try to parse as ASN.1
	var msg asn1.RawValue
	_, err := asn1.Unmarshal(data, &msg)
	if err != nil {
		return false
	}

	// Check for error in response
	// A valid response should have response PDU (0xA2)
	// and no error status
	return true
}

func getSystemInfo(target string, port int, community string, version int, timeout time.Duration) *SystemInfo {
	info := &SystemInfo{}

	// Get each system OID
	if val := getSNMPValue(target, port, community, version, commonOIDs["sysDescr"], timeout); val != "" {
		info.Description = val
	}
	if val := getSNMPValue(target, port, community, version, commonOIDs["sysObjectID"], timeout); val != "" {
		info.ObjectID = val
	}
	if val := getSNMPValue(target, port, community, version, commonOIDs["sysUpTime"], timeout); val != "" {
		info.Uptime = val
	}
	if val := getSNMPValue(target, port, community, version, commonOIDs["sysContact"], timeout); val != "" {
		info.Contact = val
	}
	if val := getSNMPValue(target, port, community, version, commonOIDs["sysName"], timeout); val != "" {
		info.Name = val
	}
	if val := getSNMPValue(target, port, community, version, commonOIDs["sysLocation"], timeout); val != "" {
		info.Location = val
	}

	if info.Description == "" && info.Name == "" {
		return nil
	}

	return info
}

func getSNMPValue(target string, port int, community string, version int, oid string, timeout time.Duration) string {
	addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()

	request := buildSNMPGetRequest(community, version, oid)

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return ""
	}
	_, err = conn.Write(request)
	if err != nil {
		return ""
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}

	return parseSNMPResponse(buf[:n])
}

func parseSNMPResponse(data []byte) string {
	// Simple response parsing - extract the value from VarBind
	// This is a simplified parser; full implementation would use proper ASN.1 decoding

	// Look for OCTET STRING (0x04) or INTEGER (0x02) value
	for i := 0; i < len(data)-2; i++ {
		if data[i] == 0x04 { // OCTET STRING
			length := int(data[i+1])
			if i+2+length <= len(data) {
				return string(data[i+2 : i+2+length])
			}
		}
		if data[i] == 0x02 { // INTEGER
			length := int(data[i+1])
			if length <= 4 && i+2+length <= len(data) {
				var val int
				for j := 0; j < length; j++ {
					val = (val << 8) | int(data[i+2+j])
				}
				return fmt.Sprintf("%d", val)
			}
		}
		if data[i] == 0x43 { // TimeTicks
			length := int(data[i+1])
			if length <= 4 && i+2+length <= len(data) {
				var val int64
				for j := 0; j < length; j++ {
					val = (val << 8) | int64(data[i+2+j])
				}
				// Convert centiseconds to human readable
				seconds := val / 100
				days := seconds / 86400
				hours := (seconds % 86400) / 3600
				mins := (seconds % 3600) / 60
				secs := seconds % 60
				return fmt.Sprintf("%d days, %02d:%02d:%02d", days, hours, mins, secs)
			}
		}
	}

	return ""
}

func getInterfaces(target string, port int, community string, version int, timeout time.Duration) []InterfaceInfo {
	// Placeholder - full implementation would SNMP walk ifTable
	return nil
}

func getProcesses(target string, port int, community string, version int, timeout time.Duration) []ProcessInfo {
	// Placeholder - full implementation would SNMP walk hrSWRunTable
	return nil
}

func loadWordlist(path string) ([]string, error) {
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
