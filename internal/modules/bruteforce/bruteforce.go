package bruteforce

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tldr-it-stepankutaj/pentakit/internal/app"
)

// Module implements the authentication testing module metadata.
type Module struct{}

func New() Module { return Module{} }

func (Module) Name() string { return "bruteforce" }
func (Module) Description() string {
	return "Authentication testing: brute-force, password spraying, default credentials"
}

// RunConfig configures the authentication testing run.
type RunConfig struct {
	Target            string
	Port              int
	Protocol          string // http, https, ssh, ftp, mysql, mssql, postgres, redis, smb, vnc
	UserList          []string
	UserFile          string
	PassList          []string
	PassFile          string
	SingleUser        string
	SinglePass        string
	PasswordSpray     bool // One password against many users
	Timeout           time.Duration
	Concurrency       int
	DelayBetween      time.Duration // Delay between attempts
	StopOnSuccess     bool
	HTTPMethod        string
	HTTPPath          string
	HTTPSuccessCode   int
	HTTPFailString    string // String that indicates failed login
	HTTPSuccessString string // String that indicates successful login
	HTTPBodyTemplate  string // Template for POST body with {{USER}} and {{PASS}} placeholders
	HTTPHeaders       map[string]string
	BasicAuth         bool
	FormAuth          bool
	UserField         string // Form field name for username
	PassField         string // Form field name for password
}

// Result represents a successful authentication attempt.
type Result struct {
	Target    string    `json:"target"`
	Port      int       `json:"port"`
	Protocol  string    `json:"protocol"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Timestamp time.Time `json:"timestamp"`
	Details   string    `json:"details,omitempty"`
}

// Statistics tracks progress.
type Statistics struct {
	TotalAttempts   int64
	SuccessCount    int64
	FailedCount     int64
	StartTime       time.Time
	CurrentUser     string
	CurrentPassword string
}

// DefaultUsernames contains common default usernames.
var DefaultUsernames = []string{
	"admin", "administrator", "root", "user", "guest", "test",
	"operator", "manager", "support", "info", "webmaster",
	"postgres", "mysql", "oracle", "sa", "dba",
	"ftp", "anonymous", "www-data", "apache", "nginx",
	"tomcat", "jenkins", "git", "svn", "backup",
	"admin@localhost", "admin@admin.com", "test@test.com",
}

// DefaultPasswords contains common default passwords.
var DefaultPasswords = []string{
	"admin", "administrator", "password", "123456", "12345678",
	"root", "toor", "pass", "test", "guest",
	"changeme", "default", "letmein", "welcome", "monkey",
	"qwerty", "abc123", "111111", "password1", "Password1",
	"admin123", "root123", "master", "login", "passw0rd",
	"", // Empty password
}

// CommonCredentials contains username:password pairs for default credentials.
var CommonCredentials = [][2]string{
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", "123456"},
	{"admin", "admin123"},
	{"root", "root"},
	{"root", "toor"},
	{"root", "password"},
	{"administrator", "administrator"},
	{"user", "user"},
	{"guest", "guest"},
	{"test", "test"},
	{"postgres", "postgres"},
	{"mysql", "mysql"},
	{"oracle", "oracle"},
	{"sa", ""},
	{"sa", "sa"},
	{"tomcat", "tomcat"},
	{"manager", "manager"},
	{"jenkins", "jenkins"},
	{"ftp", "ftp"},
	{"anonymous", ""},
	{"anonymous", "anonymous"},
}

// Run executes authentication testing.
func Run(ctx app.Context, cfg RunConfig) ([]Result, error) {
	if cfg.Target == "" {
		return nil, fmt.Errorf("target is required")
	}
	if cfg.Protocol == "" {
		cfg.Protocol = "http"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}

	// Load user list
	users := cfg.UserList
	if cfg.UserFile != "" {
		fileUsers, err := loadWordlist(cfg.UserFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load user file: %w", err)
		}
		users = append(users, fileUsers...)
	}
	if cfg.SingleUser != "" {
		users = []string{cfg.SingleUser}
	}
	if len(users) == 0 {
		users = DefaultUsernames
	}

	// Load password list
	passwords := cfg.PassList
	if cfg.PassFile != "" {
		filePass, err := loadWordlist(cfg.PassFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load password file: %w", err)
		}
		passwords = append(passwords, filePass...)
	}
	if cfg.SinglePass != "" {
		passwords = []string{cfg.SinglePass}
	}
	if len(passwords) == 0 {
		passwords = DefaultPasswords
	}

	// Generate credential pairs
	var pairs [][2]string
	if cfg.PasswordSpray {
		// Password spray: one password against all users
		for _, pass := range passwords {
			for _, user := range users {
				pairs = append(pairs, [2]string{user, pass})
			}
		}
	} else {
		// Traditional brute-force: all passwords for each user
		for _, user := range users {
			for _, pass := range passwords {
				pairs = append(pairs, [2]string{user, pass})
			}
		}
	}

	fmt.Printf("[*] Starting %s authentication testing against %s\n", cfg.Protocol, cfg.Target)
	fmt.Printf("[*] Users: %d, Passwords: %d, Total attempts: %d\n", len(users), len(passwords), len(pairs))

	if cfg.PasswordSpray {
		fmt.Println("[*] Mode: Password Spraying")
	} else {
		fmt.Println("[*] Mode: Brute-force")
	}

	// Select testing function based on protocol
	var testFunc func(context.Context, string, int, string, string, *RunConfig) (bool, string)
	switch strings.ToLower(cfg.Protocol) {
	case "http", "https":
		testFunc = testHTTP
	case "ssh":
		testFunc = testSSH
	case "ftp":
		testFunc = testFTP
	case "mysql":
		testFunc = testMySQL
	case "postgres", "postgresql":
		testFunc = testPostgres
	case "redis":
		testFunc = testRedis
	case "smb":
		testFunc = testSMB
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", cfg.Protocol)
	}

	// Execute testing
	var results []Result
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	var stats Statistics
	stats.StartTime = time.Now()

	stopChan := make(chan struct{})
	stopped := false

	for _, pair := range pairs {
		select {
		case <-stopChan:
			stopped = true
		case <-ctx.Ctx.Done():
			stopped = true
		default:
		}

		if stopped {
			break
		}

		user, pass := pair[0], pair[1]

		sem <- struct{}{}
		wg.Add(1)
		go func(user, pass string) {
			defer func() { <-sem; wg.Done() }()

			select {
			case <-stopChan:
				return
			default:
			}

			atomic.AddInt64(&stats.TotalAttempts, 1)

			testCtx, cancel := context.WithTimeout(ctx.Ctx, cfg.Timeout)
			success, details := testFunc(testCtx, cfg.Target, cfg.Port, user, pass, &cfg)
			cancel()

			if success {
				atomic.AddInt64(&stats.SuccessCount, 1)
				result := Result{
					Target:    cfg.Target,
					Port:      cfg.Port,
					Protocol:  cfg.Protocol,
					Username:  user,
					Password:  pass,
					Timestamp: time.Now(),
					Details:   details,
				}

				mu.Lock()
				results = append(results, result)
				mu.Unlock()

				displayPass := pass
				if displayPass == "" {
					displayPass = "(empty)"
				}
				fmt.Printf("[+] SUCCESS: %s:%s\n", user, displayPass)

				if cfg.StopOnSuccess {
					close(stopChan)
					stopped = true
				}
			} else {
				atomic.AddInt64(&stats.FailedCount, 1)
			}

			// Rate limiting
			if cfg.DelayBetween > 0 {
				time.Sleep(cfg.DelayBetween)
			}
		}(user, pass)
	}

	wg.Wait()

	// Print statistics
	elapsed := time.Since(stats.StartTime)
	rate := float64(stats.TotalAttempts) / elapsed.Seconds()

	fmt.Printf("\n[*] Completed in %s\n", elapsed.Round(time.Second))
	fmt.Printf("[*] Attempts: %d (%.1f/s), Success: %d, Failed: %d\n",
		stats.TotalAttempts, rate, stats.SuccessCount, stats.FailedCount)

	// Persist results
	if len(results) > 0 {
		timestamp := ctx.Now.Format("20060102-150405")
		jsonlPath := ctx.Workspace.Path("findings", fmt.Sprintf("credentials-%s.jsonl", timestamp))
		if err := writeJSONL(jsonlPath, results); err != nil {
			fmt.Printf("[!] failed to write findings: %v\n", err)
		}
	}

	return results, nil
}

func testHTTP(ctx context.Context, target string, port int, user, pass string, cfg *RunConfig) (bool, string) {
	if port == 0 {
		if cfg.Protocol == "https" {
			port = 443
		} else {
			port = 80
		}
	}

	scheme := cfg.Protocol
	if scheme == "" {
		scheme = "http"
	}

	path := cfg.HTTPPath
	if path == "" {
		path = "/"
	}

	targetURL := fmt.Sprintf("%s://%s:%d%s", scheme, target, port, path)

	client := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	method := cfg.HTTPMethod
	if method == "" {
		if cfg.FormAuth {
			method = "POST"
		} else {
			method = "GET"
		}
	}

	var body io.Reader
	var contentType string

	if cfg.FormAuth {
		// Form-based authentication
		userField := cfg.UserField
		if userField == "" {
			userField = "username"
		}
		passField := cfg.PassField
		if passField == "" {
			passField = "password"
		}

		if cfg.HTTPBodyTemplate != "" {
			// Use custom template
			bodyStr := cfg.HTTPBodyTemplate
			bodyStr = strings.ReplaceAll(bodyStr, "{{USER}}", user)
			bodyStr = strings.ReplaceAll(bodyStr, "{{PASS}}", pass)
			body = strings.NewReader(bodyStr)
			contentType = "application/x-www-form-urlencoded"
		} else {
			// Standard form encoding
			formData := url.Values{}
			formData.Set(userField, user)
			formData.Set(passField, pass)
			body = strings.NewReader(formData.Encode())
			contentType = "application/x-www-form-urlencoded"
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, body)
	if err != nil {
		return false, ""
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	// Custom headers
	for k, v := range cfg.HTTPHeaders {
		req.Header.Set(k, v)
	}

	// Basic authentication
	if cfg.BasicAuth {
		auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req.Header.Set("Authorization", "Basic "+auth)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	defer func() { _ = resp.Body.Close() }()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*100))
	bodyStr := string(bodyBytes)

	// Check success conditions
	if cfg.HTTPSuccessCode > 0 {
		if resp.StatusCode == cfg.HTTPSuccessCode {
			return true, fmt.Sprintf("Status: %d", resp.StatusCode)
		}
		return false, ""
	}

	if cfg.HTTPSuccessString != "" {
		if strings.Contains(bodyStr, cfg.HTTPSuccessString) {
			return true, "Success string matched"
		}
		return false, ""
	}

	if cfg.HTTPFailString != "" {
		if !strings.Contains(bodyStr, cfg.HTTPFailString) {
			return true, "Fail string not found"
		}
		return false, ""
	}

	// Default: 200-299 is success, 401/403 is failure
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, fmt.Sprintf("Status: %d", resp.StatusCode)
	}

	return false, ""
}

func testSSH(ctx context.Context, target string, port int, user, pass string, cfg *RunConfig) (bool, string) {
	if port == 0 {
		port = 22
	}

	addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))

	// Simple SSH banner grab to verify service, then attempt auth
	// Note: Full SSH auth would require golang.org/x/crypto/ssh package
	conn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
	if err != nil {
		return false, ""
	}
	defer func() { _ = conn.Close() }()

	// Read banner
	if err := conn.SetReadDeadline(time.Now().Add(cfg.Timeout)); err != nil {
		return false, ""
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return false, ""
	}

	// SSH auth requires proper SSH client implementation
	// This is a placeholder - actual implementation would use golang.org/x/crypto/ssh
	return false, "SSH auth not implemented - use external tool"
}

func testFTP(ctx context.Context, target string, port int, user, pass string, cfg *RunConfig) (bool, string) {
	if port == 0 {
		port = 21
	}

	addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
	if err != nil {
		return false, ""
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(cfg.Timeout)); err != nil {
		return false, ""
	}

	reader := bufio.NewReader(conn)

	// Read banner
	_, err = reader.ReadString('\n')
	if err != nil {
		return false, ""
	}

	// Send USER command
	if _, err := fmt.Fprintf(conn, "USER %s\r\n", user); err != nil {
		return false, ""
	}
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, ""
	}

	// 331 = Password required, proceed
	if !strings.HasPrefix(response, "331") {
		if strings.HasPrefix(response, "230") {
			// 230 = Already logged in (anonymous)
			return true, "Anonymous login"
		}
		return false, ""
	}

	// Send PASS command
	if _, err := fmt.Fprintf(conn, "PASS %s\r\n", pass); err != nil {
		return false, ""
	}
	response, err = reader.ReadString('\n')
	if err != nil {
		return false, ""
	}

	// 230 = Login successful
	if strings.HasPrefix(response, "230") {
		return true, strings.TrimSpace(response)
	}

	return false, ""
}

func testMySQL(_ context.Context, _ string, _ int, _, _ string, _ *RunConfig) (bool, string) {
	// MySQL auth requires proper MySQL protocol implementation
	// This is a placeholder - actual implementation would use mysql driver
	return false, "MySQL auth not implemented - use external tool"
}

func testPostgres(_ context.Context, _ string, _ int, _, _ string, _ *RunConfig) (bool, string) {
	// PostgreSQL auth requires proper PostgreSQL protocol implementation
	// This is a placeholder - actual implementation would use pq driver
	return false, "PostgreSQL auth not implemented - use external tool"
}

func testRedis(_ context.Context, target string, port int, user, pass string, cfg *RunConfig) (bool, string) {
	if port == 0 {
		port = 6379
	}

	addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
	if err != nil {
		return false, ""
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(cfg.Timeout)); err != nil {
		return false, ""
	}

	// Try AUTH command
	var cmd string
	if user != "" {
		// Redis 6+ ACL auth
		cmd = fmt.Sprintf("AUTH %s %s\r\n", user, pass)
	} else {
		// Legacy auth
		cmd = fmt.Sprintf("AUTH %s\r\n", pass)
	}

	_, err = conn.Write([]byte(cmd))
	if err != nil {
		return false, ""
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return false, ""
	}

	response := string(buf[:n])
	if strings.HasPrefix(response, "+OK") {
		return true, "Redis AUTH successful"
	}

	// Try without auth (no password required)
	conn2, err := net.DialTimeout("tcp", addr, cfg.Timeout)
	if err != nil {
		return false, ""
	}
	defer func() { _ = conn2.Close() }()

	if err := conn2.SetDeadline(time.Now().Add(cfg.Timeout)); err != nil {
		return false, ""
	}
	_, err = conn2.Write([]byte("PING\r\n"))
	if err != nil {
		return false, ""
	}

	n, err = conn2.Read(buf)
	if err != nil {
		return false, ""
	}

	response = string(buf[:n])
	if strings.HasPrefix(response, "+PONG") && pass == "" {
		return true, "Redis no auth required"
	}

	return false, ""
}

func testSMB(_ context.Context, _ string, _ int, _, _ string, _ *RunConfig) (bool, string) {
	// SMB auth requires proper SMB protocol implementation
	// This is a placeholder - actual implementation would use smb library
	return false, "SMB auth not implemented - use external tool"
}

// TestDefaultCredentials tests common default credential pairs.
func TestDefaultCredentials(ctx app.Context, target string, port int, protocol string) ([]Result, error) {
	cfg := RunConfig{
		Target:        target,
		Port:          port,
		Protocol:      protocol,
		Timeout:       10 * time.Second,
		Concurrency:   5,
		StopOnSuccess: false,
		DelayBetween:  100 * time.Millisecond,
	}

	// Use common credentials
	var users, passwords []string
	for _, cred := range CommonCredentials {
		users = append(users, cred[0])
		passwords = append(passwords, cred[1])
	}
	cfg.UserList = users
	cfg.PassList = passwords

	return Run(ctx, cfg)
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
		word := scanner.Text()
		if word != "" {
			words = append(words, word)
		}
	}
	return words, scanner.Err()
}

func writeJSONL(path string, results []Result) error {
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
	for _, r := range results {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return w.Flush()
}
