package http

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tldr-it-stepankutaj/pentakit/internal/app"
)

// Module implements the HTTP enumeration module metadata.
type Module struct{}

func New() Module { return Module{} }

func (Module) Name() string { return "http" }
func (Module) Description() string {
	return "HTTP enumeration: directory brute-force, tech fingerprinting, header analysis"
}

// RunConfig configures the HTTP enumeration run.
type RunConfig struct {
	Target          string
	Wordlist        string
	Timeout         time.Duration
	Concurrency     int
	UserAgent       string
	FollowRedirects bool
	StatusFilter    []int // only show these status codes
	Extensions      []string
	Headers         map[string]string
	TechFingerprint bool
	HeaderAnalysis  bool
	DirBruteForce   bool
	Cookies         string
}

// Result represents an HTTP finding.
type Result struct {
	URL            string            `json:"url"`
	StatusCode     int               `json:"status_code"`
	ContentLength  int64             `json:"content_length"`
	ContentType    string            `json:"content_type,omitempty"`
	Title          string            `json:"title,omitempty"`
	Server         string            `json:"server,omitempty"`
	Technologies   []string          `json:"technologies,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	SecurityIssues []string          `json:"security_issues,omitempty"`
	RedirectURL    string            `json:"redirect_url,omitempty"`
}

// TechSignature represents a technology fingerprint.
type TechSignature struct {
	Name       string
	HeaderKey  string
	HeaderVal  *regexp.Regexp
	BodyMatch  *regexp.Regexp
	CookieName string
	URLPath    string
}

// Common technology signatures.
var techSignatures = []TechSignature{
	// Web servers
	{Name: "Apache", HeaderKey: "Server", HeaderVal: regexp.MustCompile(`(?i)apache`)},
	{Name: "Nginx", HeaderKey: "Server", HeaderVal: regexp.MustCompile(`(?i)nginx`)},
	{Name: "IIS", HeaderKey: "Server", HeaderVal: regexp.MustCompile(`(?i)microsoft-iis`)},
	{Name: "LiteSpeed", HeaderKey: "Server", HeaderVal: regexp.MustCompile(`(?i)litespeed`)},
	{Name: "Caddy", HeaderKey: "Server", HeaderVal: regexp.MustCompile(`(?i)caddy`)},

	// Frameworks
	{Name: "PHP", HeaderKey: "X-Powered-By", HeaderVal: regexp.MustCompile(`(?i)php`)},
	{Name: "ASP.NET", HeaderKey: "X-Powered-By", HeaderVal: regexp.MustCompile(`(?i)asp\.net`)},
	{Name: "Express", HeaderKey: "X-Powered-By", HeaderVal: regexp.MustCompile(`(?i)express`)},
	{Name: "Django", BodyMatch: regexp.MustCompile(`(?i)csrfmiddlewaretoken|django`)},
	{Name: "Rails", HeaderKey: "X-Powered-By", HeaderVal: regexp.MustCompile(`(?i)phusion|rails`)},
	{Name: "Laravel", CookieName: "laravel_session"},
	{Name: "Spring", HeaderKey: "X-Application-Context", HeaderVal: regexp.MustCompile(`.+`)},

	// CMS
	{Name: "WordPress", BodyMatch: regexp.MustCompile(`(?i)wp-content|wp-includes|wordpress`)},
	{Name: "Drupal", BodyMatch: regexp.MustCompile(`(?i)drupal|sites/all|sites/default`)},
	{Name: "Joomla", BodyMatch: regexp.MustCompile(`(?i)joomla|/administrator/`)},
	{Name: "Magento", BodyMatch: regexp.MustCompile(`(?i)magento|mage/cookies`)},
	{Name: "Shopify", BodyMatch: regexp.MustCompile(`(?i)shopify|cdn\.shopify\.com`)},

	// JavaScript frameworks
	{Name: "React", BodyMatch: regexp.MustCompile(`(?i)react|_reactRootContainer|__NEXT_DATA__`)},
	{Name: "Angular", BodyMatch: regexp.MustCompile(`(?i)ng-app|ng-controller|angular\.js`)},
	{Name: "Vue.js", BodyMatch: regexp.MustCompile(`(?i)vue\.js|v-bind|v-model`)},
	{Name: "jQuery", BodyMatch: regexp.MustCompile(`(?i)jquery`)},

	// CDN/Proxy
	{Name: "Cloudflare", HeaderKey: "CF-Ray", HeaderVal: regexp.MustCompile(`.+`)},
	{Name: "AWS CloudFront", HeaderKey: "X-Amz-Cf-Id", HeaderVal: regexp.MustCompile(`.+`)},
	{Name: "Akamai", HeaderKey: "X-Akamai-Transformed", HeaderVal: regexp.MustCompile(`.+`)},
	{Name: "Varnish", HeaderKey: "X-Varnish", HeaderVal: regexp.MustCompile(`.+`)},

	// Security
	{Name: "ModSecurity", HeaderKey: "Server", HeaderVal: regexp.MustCompile(`(?i)mod_security`)},
	{Name: "AWS WAF", HeaderKey: "X-Amzn-Waf-Action", HeaderVal: regexp.MustCompile(`.+`)},
}

// Security headers to check.
var securityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"X-XSS-Protection",
	"Referrer-Policy",
	"Permissions-Policy",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Resource-Policy",
	"Cross-Origin-Embedder-Policy",
}

// DefaultWordlist contains common directory/file names.
var DefaultWordlist = []string{
	"admin", "administrator", "login", "wp-admin", "wp-login.php", "phpmyadmin",
	"dashboard", "cpanel", "webmail", "mail", "email", "ftp", "sftp",
	"api", "api/v1", "api/v2", "graphql", "rest", "swagger", "docs", "documentation",
	"backup", "backups", "bak", "old", "temp", "tmp", "test", "testing", "dev",
	"staging", "stage", "uat", "demo", "beta", "alpha", "sandbox",
	".git", ".git/config", ".git/HEAD", ".svn", ".svn/entries", ".hg",
	".env", ".env.local", ".env.prod", ".env.backup", "config", "configuration",
	"wp-config.php", "config.php", "settings.php", "database.yml", "application.yml",
	"robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
	".htaccess", ".htpasswd", "web.config", "nginx.conf",
	"server-status", "server-info", "status", "health", "healthcheck", "ping",
	"debug", "trace", "error", "errors", "log", "logs", "access.log", "error.log",
	"console", "shell", "cmd", "command", "terminal", "exec",
	"upload", "uploads", "files", "file", "download", "downloads", "media", "images",
	"img", "assets", "static", "public", "private", "data", "db", "database",
	"sql", "mysql", "pgsql", "sqlite", "dump", "export", "import",
	"user", "users", "account", "accounts", "profile", "profiles", "register", "signup",
	"password", "passwd", "pwd", "reset", "forgot", "recovery",
	"search", "query", "find", "filter",
	"payment", "pay", "checkout", "cart", "shop", "store", "order", "orders",
	"invoice", "invoices", "billing", "subscription",
	"portal", "gateway", "proxy", "redirect", "callback", "webhook", "hook",
	"cgi-bin", "cgi", "bin", "scripts", "includes", "inc",
	"vendor", "node_modules", "bower_components", "packages",
	"xmlrpc.php", "wp-json", "feed", "rss", "atom",
	"jenkins", "travis", "circleci", "gitlab-ci", "github", "bitbucket",
	"prometheus", "metrics", "grafana", "kibana", "elasticsearch",
	"actuator", "actuator/health", "actuator/info", "actuator/env",
	"manager", "manager/html", "jmx-console", "web-console", "invoker",
}

// Run executes HTTP enumeration.
func Run(ctx app.Context, cfg RunConfig) ([]Result, error) {
	if cfg.Target == "" {
		return nil, fmt.Errorf("target URL is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 20
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	}

	// Normalize target URL
	targetURL, err := normalizeURL(cfg.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	client := createHTTPClient(cfg)
	var allResults []Result

	// Initial request for fingerprinting
	fmt.Printf("[*] Analyzing %s\n", targetURL)
	initialResult := analyzeURL(ctx.Ctx, client, targetURL, cfg)
	if initialResult != nil {
		allResults = append(allResults, *initialResult)

		fmt.Printf("[+] Status: %d | Size: %d | Server: %s\n",
			initialResult.StatusCode, initialResult.ContentLength, initialResult.Server)

		if len(initialResult.Technologies) > 0 {
			fmt.Printf("[+] Technologies: %s\n", strings.Join(initialResult.Technologies, ", "))
		}

		if cfg.HeaderAnalysis && len(initialResult.SecurityIssues) > 0 {
			fmt.Println("[!] Security Issues:")
			for _, issue := range initialResult.SecurityIssues {
				fmt.Printf("    - %s\n", issue)
			}
		}
	}

	// Directory brute-force
	if cfg.DirBruteForce {
		fmt.Printf("\n[*] Starting directory brute-force...\n")

		wordlist := DefaultWordlist
		if cfg.Wordlist != "" {
			if wl, err := loadWordlist(cfg.Wordlist); err == nil {
				wordlist = wl
			} else {
				fmt.Printf("[!] Failed to load wordlist: %v, using default\n", err)
			}
		}

		// Expand wordlist with extensions
		expandedList := expandWordlist(wordlist, cfg.Extensions)

		dirResults := bruteForceDirectories(ctx.Ctx, client, targetURL, expandedList, cfg)
		fmt.Printf("[+] Found %d endpoints\n", len(dirResults))
		allResults = append(allResults, dirResults...)
	}

	// Sort results by URL
	sort.Slice(allResults, func(i, j int) bool {
		return allResults[i].URL < allResults[j].URL
	})

	// Persist results
	timestamp := ctx.Now.Format("20060102-150405")
	jsonlPath := ctx.Workspace.Path("findings", fmt.Sprintf("http-%s.jsonl", timestamp))
	if err := writeJSONL(jsonlPath, allResults); err != nil {
		fmt.Printf("[!] failed to write findings: %v\n", err)
	}

	return allResults, nil
}

func normalizeURL(target string) (string, error) {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

func createHTTPClient(cfg RunConfig) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Allow self-signed certs for pentesting
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}

	if !cfg.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client
}

func analyzeURL(ctx context.Context, client *http.Client, targetURL string, cfg RunConfig) *Result {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", cfg.UserAgent)
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
	if cfg.Cookies != "" {
		req.Header.Set("Cookie", cfg.Cookies)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // Limit to 1MB

	result := &Result{
		URL:           targetURL,
		StatusCode:    resp.StatusCode,
		ContentLength: resp.ContentLength,
		ContentType:   resp.Header.Get("Content-Type"),
		Server:        resp.Header.Get("Server"),
		Headers:       make(map[string]string),
	}

	// Extract title
	if titleMatch := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`).FindSubmatch(body); len(titleMatch) > 1 {
		result.Title = strings.TrimSpace(string(titleMatch[1]))
	}

	// Copy relevant headers
	for k, v := range resp.Header {
		if len(v) > 0 {
			result.Headers[k] = v[0]
		}
	}

	// Handle redirects
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		result.RedirectURL = resp.Header.Get("Location")
	}

	// Technology fingerprinting
	if cfg.TechFingerprint {
		result.Technologies = fingerprintTechnologies(resp.Header, body, resp.Cookies())
	}

	// Security header analysis
	if cfg.HeaderAnalysis {
		result.SecurityIssues = analyzeSecurityHeaders(resp.Header, targetURL)
	}

	return result
}

func fingerprintTechnologies(headers http.Header, body []byte, cookies []*http.Cookie) []string {
	var techs []string
	seen := make(map[string]bool)

	for _, sig := range techSignatures {
		if seen[sig.Name] {
			continue
		}

		matched := false

		// Check header
		if sig.HeaderKey != "" && sig.HeaderVal != nil {
			if val := headers.Get(sig.HeaderKey); val != "" {
				if sig.HeaderVal.MatchString(val) {
					matched = true
				}
			}
		}

		// Check body
		if !matched && sig.BodyMatch != nil {
			if sig.BodyMatch.Match(body) {
				matched = true
			}
		}

		// Check cookies
		if !matched && sig.CookieName != "" {
			for _, cookie := range cookies {
				if strings.EqualFold(cookie.Name, sig.CookieName) {
					matched = true
					break
				}
			}
		}

		if matched {
			techs = append(techs, sig.Name)
			seen[sig.Name] = true
		}
	}

	return techs
}

func analyzeSecurityHeaders(headers http.Header, targetURL string) []string {
	var issues []string

	// Check for missing security headers
	for _, h := range securityHeaders {
		if headers.Get(h) == "" {
			issues = append(issues, fmt.Sprintf("Missing header: %s", h))
		}
	}

	// Check HSTS on HTTPS
	if strings.HasPrefix(targetURL, "https://") {
		hsts := headers.Get("Strict-Transport-Security")
		if hsts == "" {
			issues = append(issues, "HTTPS without HSTS header")
		} else if !strings.Contains(hsts, "includeSubDomains") {
			issues = append(issues, "HSTS without includeSubDomains")
		}
	}

	// Check X-Frame-Options
	xfo := headers.Get("X-Frame-Options")
	if xfo != "" && !strings.EqualFold(xfo, "DENY") && !strings.EqualFold(xfo, "SAMEORIGIN") {
		issues = append(issues, fmt.Sprintf("Weak X-Frame-Options: %s", xfo))
	}

	// Check Content-Type-Options
	xcto := headers.Get("X-Content-Type-Options")
	if xcto != "" && !strings.EqualFold(xcto, "nosniff") {
		issues = append(issues, fmt.Sprintf("Invalid X-Content-Type-Options: %s", xcto))
	}

	// Check for information disclosure
	if server := headers.Get("Server"); server != "" {
		if regexp.MustCompile(`\d+\.\d+`).MatchString(server) {
			issues = append(issues, fmt.Sprintf("Server version disclosure: %s", server))
		}
	}

	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		issues = append(issues, fmt.Sprintf("X-Powered-By disclosure: %s", poweredBy))
	}

	// Check for sensitive cookies without flags
	for _, cookie := range headers.Values("Set-Cookie") {
		cookieLower := strings.ToLower(cookie)
		if strings.Contains(cookieLower, "session") || strings.Contains(cookieLower, "token") ||
			strings.Contains(cookieLower, "auth") {
			if !strings.Contains(cookieLower, "httponly") {
				issues = append(issues, "Sensitive cookie without HttpOnly flag")
			}
			if !strings.Contains(cookieLower, "secure") && strings.HasPrefix(targetURL, "https://") {
				issues = append(issues, "Sensitive cookie without Secure flag")
			}
			if !strings.Contains(cookieLower, "samesite") {
				issues = append(issues, "Cookie without SameSite attribute")
			}
		}
	}

	return issues
}

func bruteForceDirectories(ctx context.Context, client *http.Client, baseURL string, wordlist []string, cfg RunConfig) []Result {
	var results []Result
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup

	baseURL = strings.TrimSuffix(baseURL, "/")

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

			testURL := fmt.Sprintf("%s/%s", baseURL, word)

			req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
			if err != nil {
				return
			}

			req.Header.Set("User-Agent", cfg.UserAgent)
			for k, v := range cfg.Headers {
				req.Header.Set(k, v)
			}
			if cfg.Cookies != "" {
				req.Header.Set("Cookie", cfg.Cookies)
			}

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			// Filter by status code
			if len(cfg.StatusFilter) > 0 {
				found := false
				for _, s := range cfg.StatusFilter {
					if resp.StatusCode == s {
						found = true
						break
					}
				}
				if !found {
					return
				}
			} else {
				// Default: skip 404
				if resp.StatusCode == 404 {
					return
				}
			}

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*100)) // 100KB limit for dir bruteforce

			result := Result{
				URL:           testURL,
				StatusCode:    resp.StatusCode,
				ContentLength: resp.ContentLength,
				ContentType:   resp.Header.Get("Content-Type"),
				Server:        resp.Header.Get("Server"),
			}

			// Extract title for interesting pages
			if titleMatch := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`).FindSubmatch(body); len(titleMatch) > 1 {
				result.Title = strings.TrimSpace(string(titleMatch[1]))
			}

			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				result.RedirectURL = resp.Header.Get("Location")
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()

			// Print interesting findings
			statusColor := ""
			switch {
			case resp.StatusCode >= 200 && resp.StatusCode < 300:
				statusColor = "200"
			case resp.StatusCode >= 300 && resp.StatusCode < 400:
				statusColor = "30x"
			case resp.StatusCode >= 400 && resp.StatusCode < 500:
				statusColor = "4xx"
			default:
				statusColor = "5xx"
			}

			extra := ""
			if result.RedirectURL != "" {
				extra = fmt.Sprintf(" -> %s", result.RedirectURL)
			} else if result.Title != "" {
				extra = fmt.Sprintf(" [%s]", truncate(result.Title, 30))
			}

			fmt.Printf("[%s] %s (size: %d)%s\n", statusColor, testURL, resp.ContentLength, extra)
		}()
	}

	wg.Wait()
	return results
}

func expandWordlist(words []string, extensions []string) []string {
	if len(extensions) == 0 {
		return words
	}

	var expanded []string
	for _, word := range words {
		expanded = append(expanded, word)
		for _, ext := range extensions {
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			expanded = append(expanded, word+ext)
		}
	}
	return expanded
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

func truncate(s string, maxLen int) string {
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
