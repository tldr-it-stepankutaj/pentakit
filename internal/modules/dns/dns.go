package dns

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tldr-it-stepankutaj/pentakit/internal/app"
)

// Module implements the DNS enumeration module metadata.
type Module struct{}

func New() Module { return Module{} }

func (Module) Name() string { return "dns" }
func (Module) Description() string {
	return "DNS enumeration: subdomains, zone transfer, reverse lookup"
}

// RunConfig configures the DNS enumeration run.
type RunConfig struct {
	Domain        string
	Wordlist      string   // path to subdomain wordlist
	Nameservers   []string // custom nameservers
	Timeout       time.Duration
	Concurrency   int
	ZoneTransfer  bool
	ReverseLookup bool
	IPRange       string // CIDR for reverse lookup
	BruteForce    bool
	CTLogs        bool // use Certificate Transparency logs (crt.sh)
}

// Result represents a DNS finding.
type Result struct {
	Type       string   `json:"type"` // A, AAAA, CNAME, MX, NS, TXT, PTR, ZONE, SUBDOMAIN
	Domain     string   `json:"domain"`
	Name       string   `json:"name,omitempty"`
	Value      string   `json:"value,omitempty"`
	Values     []string `json:"values,omitempty"`
	TTL        int      `json:"ttl,omitempty"`
	Additional string   `json:"additional,omitempty"`
}

// Record is an alias for Result (used by TUI)
type Record = Result

// DefaultWordlist contains common subdomain prefixes.
var DefaultWordlist = []string{
	// Common web
	"www", "www1", "www2", "www3", "web", "web1", "web2", "site", "portal",
	"m", "mobile", "app", "apps", "api", "api1", "api2", "api-v1", "api-v2",

	// Mail
	"mail", "mail1", "mail2", "webmail", "smtp", "pop", "pop3", "imap",
	"mx", "mx1", "mx2", "mx3", "exchange", "owa", "autodiscover",

	// DNS/NS
	"ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",

	// FTP/Files
	"ftp", "ftp1", "ftp2", "sftp", "files", "file", "upload", "download",
	"media", "images", "img", "assets", "static", "cdn", "content",

	// Dev/CI/CD
	"dev", "dev1", "dev2", "development", "staging", "stage", "test", "testing",
	"beta", "alpha", "demo", "preview", "uat", "qa", "prod", "production",
	"sandbox", "lab", "local", "localhost",
	"git", "gitlab", "github", "bitbucket", "svn", "cvs",
	"jenkins", "ci", "cd", "build", "deploy", "release",
	"sonar", "sonarqube", "nexus", "artifactory", "satis",
	"argocd", "argo", "drone", "travis", "circleci",

	// Containers/K8s
	"docker", "registry", "harbor", "quay",
	"k8s", "kubernetes", "kube", "kubectl", "rancher", "openshift",
	"k8s-0", "k8s-1", "k8s-2", "k8s-3", "k8s-4", "k8s-5", "k8s-6", "k8s-7", "k8s-8", "k8s-9",
	"node", "node1", "node2", "node3", "worker", "worker1", "worker2",
	"master", "master1", "master2", "control", "controller",
	"longhorn", "helm", "tiller",

	// Databases
	"db", "db1", "db2", "database", "data", "data01", "data02", "data03",
	"sql", "mysql", "mariadb", "postgres", "postgresql", "pg", "pg-01", "pg-db", "pg-db-dev",
	"mongodb", "mongo", "redis", "memcache", "memcached",
	"elastic", "elasticsearch", "es", "kibana", "logstash",
	"influx", "influxdb", "grafana", "prometheus",

	// Cloud
	"cloud", "aws", "azure", "gcp", "do", "digitalocean", "linode", "vultr",
	"s3", "minio", "storage", "bucket", "blob",

	// Auth/Security
	"auth", "oauth", "sso", "login", "secure", "security",
	"ldap", "ad", "active-directory", "keycloak", "okta", "saml",
	"vault", "secrets", "crypto",

	// Admin/Management
	"admin", "administrator", "manage", "manager", "management", "mng",
	"console", "panel", "dashboard", "control", "cpanel", "whm",
	"monitoring", "monitor", "nagios", "zabbix", "icinga",
	"logs", "log", "logging", "syslog", "graylog", "splunk",
	"gvm", "openvas", "nessus",

	// Network/VPN
	"vpn", "vpn1", "vpn2", "openvpn", "wireguard",
	"gateway", "gw", "router", "firewall", "fw", "proxy", "cache", "squid",
	"lb", "loadbalancer", "haproxy", "nginx", "apache", "traefik",

	// Messaging/Queue
	"rabbit", "rabbitmq", "kafka", "activemq", "mq", "queue", "amqp",
	"n8n", "airflow", "celery",

	// Collaboration
	"wiki", "confluence", "jira", "redmine", "trac", "bugzilla",
	"slack", "teams", "mattermost", "rocket", "chat",
	"zoom", "webex", "meet", "conference", "video", "lyncdiscover", "sip",
	"docs", "doc", "documentation", "help", "support", "kb", "knowledge",
	"pages", "blog", "cms", "wordpress", "drupal", "joomla",

	// Business
	"shop", "store", "ecommerce", "cart", "checkout", "payment", "pay",
	"crm", "erp", "sap", "hr", "finance", "accounting",
	"intranet", "extranet", "internal", "external",
	"corp", "corporate", "office", "remote", "work",

	// VM/Hosts
	"vm", "vm01", "vm02", "vm03", "vm1", "vm2", "vm3",
	"srv", "srv1", "srv2", "srv01", "srv02",
	"server", "server1", "server2", "host", "host1", "host2",
	"box", "vps", "vps1", "vps2",

	// Backup/Archive
	"backup", "bak", "backups", "archive", "old", "new", "legacy",
	"dr", "disaster", "recovery", "replica", "mirror",

	// Status/Health
	"status", "health", "uptime", "ping", "check",

	// Misc
	"home", "default", "main", "root", "public", "private",
	"report", "reports", "analytics", "stats", "statistics",
	"v1", "v2", "v3", "version", "latest",
}

// Run executes DNS enumeration.
func Run(ctx app.Context, cfg RunConfig) ([]Result, error) {
	if cfg.Domain == "" && cfg.IPRange == "" {
		return nil, fmt.Errorf("domain or IP range is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 50
	}
	if len(cfg.Nameservers) == 0 {
		cfg.Nameservers = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}

	var allResults []Result
	var mu sync.Mutex

	// Basic DNS records lookup
	if cfg.Domain != "" {
		fmt.Printf("[*] Enumerating DNS records for %s\n", cfg.Domain)
		records := lookupBasicRecords(cfg.Domain, cfg.Timeout)
		allResults = append(allResults, records...)

		for _, r := range records {
			printResult(r)
		}
	}

	// Zone transfer attempt
	if cfg.ZoneTransfer && cfg.Domain != "" {
		fmt.Printf("\n[*] Attempting zone transfer for %s\n", cfg.Domain)
		zoneResults := attemptZoneTransfer(cfg.Domain, cfg.Timeout)
		if len(zoneResults) > 0 {
			fmt.Printf("[+] Zone transfer successful! Found %d records\n", len(zoneResults))
			allResults = append(allResults, zoneResults...)
		} else {
			fmt.Println("[-] Zone transfer failed or not allowed")
		}
	}

	// Certificate Transparency logs lookup
	if cfg.CTLogs && cfg.Domain != "" {
		fmt.Printf("\n[*] Querying Certificate Transparency logs for %s\n", cfg.Domain)
		ctSubdomains, err := queryCTLogs(cfg.Domain, cfg.Timeout)
		if err != nil {
			fmt.Printf("[!] CT logs query failed: %v\n", err)
		} else {
			fmt.Printf("[+] Found %d unique subdomains in CT logs\n", len(ctSubdomains))
			// Resolve each subdomain found in CT logs
			ctResults := resolveSubdomains(ctx.Ctx, ctSubdomains, cfg.Nameservers[0], cfg.Timeout, cfg.Concurrency)
			fmt.Printf("[+] Resolved %d subdomains from CT logs\n", len(ctResults))
			allResults = append(allResults, ctResults...)
			for _, r := range ctResults {
				printResult(r)
			}
		}
	}

	// Subdomain brute-force
	if cfg.BruteForce && cfg.Domain != "" {
		fmt.Printf("\n[*] Brute-forcing subdomains for %s\n", cfg.Domain)

		wordlist := DefaultWordlist
		if cfg.Wordlist != "" {
			if wl, err := loadWordlist(cfg.Wordlist); err == nil {
				wordlist = wl
			} else {
				fmt.Printf("[!] Failed to load wordlist: %v, using default\n", err)
			}
		}

		subResults := bruteForceSubdomains(ctx.Ctx, cfg.Domain, wordlist, cfg.Nameservers[0], cfg.Timeout, cfg.Concurrency)
		fmt.Printf("[+] Found %d subdomains\n", len(subResults))
		allResults = append(allResults, subResults...)

		for _, r := range subResults {
			printResult(r)
		}
	}

	// Reverse DNS lookup
	if cfg.ReverseLookup && cfg.IPRange != "" {
		fmt.Printf("\n[*] Performing reverse DNS lookup on %s\n", cfg.IPRange)

		ips, err := expandCIDR(cfg.IPRange)
		if err != nil {
			return nil, fmt.Errorf("invalid IP range: %w", err)
		}

		sem := make(chan struct{}, cfg.Concurrency)
		var wg sync.WaitGroup

		for _, ip := range ips {
			ip := ip
			sem <- struct{}{}
			wg.Add(1)
			go func() {
				defer func() { <-sem; wg.Done() }()

				names, err := net.LookupAddr(ip)
				if err == nil && len(names) > 0 {
					result := Result{
						Type:   "PTR",
						Domain: ip,
						Values: names,
					}
					mu.Lock()
					allResults = append(allResults, result)
					mu.Unlock()
					fmt.Printf("%s -> %s\n", ip, strings.Join(names, ", "))
				}
			}()
		}
		wg.Wait()
	}

	// Sort and deduplicate
	sort.Slice(allResults, func(i, j int) bool {
		if allResults[i].Type != allResults[j].Type {
			return allResults[i].Type < allResults[j].Type
		}
		return allResults[i].Domain < allResults[j].Domain
	})

	// Persist results
	timestamp := ctx.Now.Format("20060102-150405")
	jsonlPath := ctx.Workspace.Path("findings", fmt.Sprintf("dns-%s.jsonl", timestamp))
	if err := writeJSONL(jsonlPath, allResults); err != nil {
		fmt.Printf("[!] failed to write findings: %v\n", err)
	}

	return allResults, nil
}

func lookupBasicRecords(domain string, timeout time.Duration) []Result {
	var results []Result
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout*5)
	defer cancel()

	// A records
	if ips, err := resolver.LookupIP(ctx, "ip4", domain); err == nil {
		for _, ip := range ips {
			results = append(results, Result{
				Type:   "A",
				Domain: domain,
				Value:  ip.String(),
			})
		}
	}

	// AAAA records
	if ips, err := resolver.LookupIP(ctx, "ip6", domain); err == nil {
		for _, ip := range ips {
			results = append(results, Result{
				Type:   "AAAA",
				Domain: domain,
				Value:  ip.String(),
			})
		}
	}

	// MX records
	if mxs, err := resolver.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxs {
			results = append(results, Result{
				Type:       "MX",
				Domain:     domain,
				Value:      mx.Host,
				Additional: fmt.Sprintf("priority: %d", mx.Pref),
			})
		}
	}

	// NS records
	if nss, err := resolver.LookupNS(ctx, domain); err == nil {
		for _, ns := range nss {
			results = append(results, Result{
				Type:   "NS",
				Domain: domain,
				Value:  ns.Host,
			})
		}
	}

	// TXT records
	if txts, err := resolver.LookupTXT(ctx, domain); err == nil {
		for _, txt := range txts {
			results = append(results, Result{
				Type:   "TXT",
				Domain: domain,
				Value:  txt,
			})
		}
	}

	// CNAME
	if cname, err := resolver.LookupCNAME(ctx, domain); err == nil && cname != domain+"." {
		results = append(results, Result{
			Type:   "CNAME",
			Domain: domain,
			Value:  cname,
		})
	}

	return results
}

func attemptZoneTransfer(domain string, timeout time.Duration) []Result {
	var results []Result

	// First, get NS records
	nss, err := net.LookupNS(domain)
	if err != nil {
		return results
	}

	for _, ns := range nss {
		nsHost := strings.TrimSuffix(ns.Host, ".")

		// Connect to nameserver port 53 TCP for zone transfer
		conn, err := net.DialTimeout("tcp", nsHost+":53", timeout)
		if err != nil {
			continue
		}

		// Build AXFR query (simplified - real implementation would need full DNS packet)
		// This is a basic attempt - full AXFR requires proper DNS packet construction
		query := buildAXFRQuery(domain)
		conn.SetDeadline(time.Now().Add(timeout * 3))
		_, err = conn.Write(query)
		if err != nil {
			conn.Close()
			continue
		}

		// Read response
		buf := make([]byte, 65535)
		n, err := conn.Read(buf)
		conn.Close()

		if err == nil && n > 12 {
			// Check for successful response (simplified check)
			// Real implementation would parse the full DNS response
			if buf[3]&0x0F == 0 { // No error in response
				results = append(results, Result{
					Type:       "ZONE",
					Domain:     domain,
					Value:      nsHost,
					Additional: "Zone transfer may be possible - manual verification recommended",
				})
			}
		}
	}

	return results
}

func buildAXFRQuery(domain string) []byte {
	// Simplified AXFR query construction
	// Transaction ID (2 bytes) + Flags (2 bytes) + Questions (2 bytes) +
	// Answer/Authority/Additional RR counts (6 bytes) + Query
	query := make([]byte, 0, 512)

	// Transaction ID
	query = append(query, 0x00, 0x01)
	// Flags: Standard query
	query = append(query, 0x00, 0x00)
	// Questions: 1
	query = append(query, 0x00, 0x01)
	// Answer RRs: 0
	query = append(query, 0x00, 0x00)
	// Authority RRs: 0
	query = append(query, 0x00, 0x00)
	// Additional RRs: 0
	query = append(query, 0x00, 0x00)

	// Query name
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		query = append(query, byte(len(part)))
		query = append(query, []byte(part)...)
	}
	query = append(query, 0x00) // End of name

	// Query type: AXFR (252)
	query = append(query, 0x00, 0xFC)
	// Query class: IN (1)
	query = append(query, 0x00, 0x01)

	// Prepend length for TCP
	length := len(query)
	result := make([]byte, length+2)
	result[0] = byte(length >> 8)
	result[1] = byte(length)
	copy(result[2:], query)

	return result
}

func bruteForceSubdomains(ctx context.Context, domain string, wordlist []string, nameserver string, timeout time.Duration, concurrency int) []Result {
	var results []Result
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", nameserver)
		},
	}

	for _, word := range wordlist {
		word := word
		select {
		case <-ctx.Done():
			break
		default:
		}

		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()

			subdomain := fmt.Sprintf("%s.%s", word, domain)
			lookupCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			// First check CNAME
			cname, err := resolver.LookupCNAME(lookupCtx, subdomain)
			if err == nil && cname != "" && cname != subdomain+"." {
				mu.Lock()
				results = append(results, Result{
					Type:   "CNAME",
					Domain: subdomain,
					Value:  strings.TrimSuffix(cname, "."),
				})
				mu.Unlock()
			}

			// Then check A records
			ips, err := resolver.LookupIP(lookupCtx, "ip4", subdomain)
			if err == nil && len(ips) > 0 {
				var ipStrs []string
				for _, ip := range ips {
					ipStrs = append(ipStrs, ip.String())
				}
				mu.Lock()
				results = append(results, Result{
					Type:   "SUBDOMAIN",
					Domain: subdomain,
					Values: ipStrs,
				})
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return results
}

// crtshEntry represents a single entry from crt.sh JSON response
type crtshEntry struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

// queryCTLogs queries crt.sh for subdomains from Certificate Transparency logs
func queryCTLogs(domain string, timeout time.Duration) ([]string, error) {
	client := &http.Client{
		Timeout: timeout * 10, // CT logs can be slow
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}

	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to query crt.sh: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Extract unique subdomains
	seen := make(map[string]bool)
	var subdomains []string

	for _, entry := range entries {
		// name_value can contain multiple domains separated by newlines
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(strings.ToLower(name))
			// Skip wildcards and empty
			if name == "" || strings.HasPrefix(name, "*") {
				continue
			}
			// Must be subdomain of our target
			if !strings.HasSuffix(name, "."+domain) && name != domain {
				continue
			}
			if !seen[name] {
				seen[name] = true
				subdomains = append(subdomains, name)
			}
		}
	}

	return subdomains, nil
}

// resolveSubdomains resolves a list of subdomains to their IP addresses
func resolveSubdomains(ctx context.Context, subdomains []string, nameserver string, timeout time.Duration, concurrency int) []Result {
	var results []Result
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", nameserver)
		},
	}

	for _, subdomain := range subdomains {
		subdomain := subdomain
		select {
		case <-ctx.Done():
			break
		default:
		}

		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()

			lookupCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			// Check CNAME
			cname, err := resolver.LookupCNAME(lookupCtx, subdomain)
			if err == nil && cname != "" && cname != subdomain+"." {
				mu.Lock()
				results = append(results, Result{
					Type:   "CNAME",
					Domain: subdomain,
					Value:  strings.TrimSuffix(cname, "."),
				})
				mu.Unlock()
			}

			// Check A records
			ips, err := resolver.LookupIP(lookupCtx, "ip4", subdomain)
			if err == nil && len(ips) > 0 {
				var ipStrs []string
				for _, ip := range ips {
					ipStrs = append(ipStrs, ip.String())
				}
				mu.Lock()
				results = append(results, Result{
					Type:   "SUBDOMAIN",
					Domain: subdomain,
					Values: ipStrs,
				})
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return results
}

func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

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

func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try as single IP
		if net.ParseIP(cidr) != nil {
			return []string{cidr}, nil
		}
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast for IPv4
	if ip.To4() != nil && len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

func printResult(r Result) {
	switch r.Type {
	case "SUBDOMAIN":
		fmt.Printf("[SUBDOMAIN] %s -> %s\n", r.Domain, strings.Join(r.Values, ", "))
	case "PTR":
		fmt.Printf("[PTR] %s -> %s\n", r.Domain, strings.Join(r.Values, ", "))
	default:
		if r.Additional != "" {
			fmt.Printf("[%s] %s -> %s (%s)\n", r.Type, r.Domain, r.Value, r.Additional)
		} else {
			fmt.Printf("[%s] %s -> %s\n", r.Type, r.Domain, r.Value)
		}
	}
}

func writeJSONL(path string, results []Result) error {
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
	for _, r := range results {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return w.Flush()
}
