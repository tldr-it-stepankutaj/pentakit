package pentakit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/tldr-it-stepankutaj/pentakit/internal/app"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/bruteforce"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/dns"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/http"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/nuclei"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/recon"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/services"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/smb"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/snmp"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/ssl"
	"github.com/tldr-it-stepankutaj/pentakit/internal/reports"
	"github.com/tldr-it-stepankutaj/pentakit/internal/tui"
	"github.com/tldr-it-stepankutaj/pentakit/internal/workflow"
	"github.com/tldr-it-stepankutaj/pentakit/internal/workspace"
	"github.com/tldr-it-stepankutaj/pentakit/pkg/version"
)

var rootCmd = &cobra.Command{
	Use:   "pentakit",
	Short: "Pentakit: extensible pentest toolkit (CLI/TUI)",
	Long:  "Pentakit is an extensible Go-based toolkit for repeatable pentest workflows. Use CLI by default or TUI with --tui.",
	RunE: func(cmd *cobra.Command, args []string) error {
		useTUI := viper.GetBool("tui")
		if useTUI {
			cfg := app.MustLoadConfigFromViper()
			ws, err := workspace.Ensure(cfg.Workspace)
			if err != nil {
				return err
			}
			appCtx := app.Context{
				Ctx:       context.Background(),
				Config:    cfg,
				Workspace: ws,
				Now:       time.Now(),
			}
			return tui.Run(appCtx)
		}
		return cmd.Help()
	},
}

func init() {
	// Persistent flags (available to all subcommands).
	rootCmd.PersistentFlags().String("workspace", "./work", "Path to workspace root")
	rootCmd.PersistentFlags().Bool("tui", false, "Run in TUI mode")
	rootCmd.PersistentFlags().String("log-level", "info", "Log level (debug|info|warn|error)")
	rootCmd.PersistentFlags().Duration("timeout", 30*time.Second, "Default operation timeout")

	// Bind flags to Viper.
	_ = viper.BindPFlag("workspace", rootCmd.PersistentFlags().Lookup("workspace"))
	_ = viper.BindPFlag("tui", rootCmd.PersistentFlags().Lookup("tui"))
	_ = viper.BindPFlag("log_level", rootCmd.PersistentFlags().Lookup("log-level"))
	_ = viper.BindPFlag("timeout", rootCmd.PersistentFlags().Lookup("timeout"))

	// Env support: PENTAKIT_WORKSPACE, PENTAKIT_TUI, etc.
	viper.SetEnvPrefix("PENTAKIT")
	viper.AutomaticEnv()

	// Register subcommands.
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(reconCmd)
	rootCmd.AddCommand(servicesCmd)
	rootCmd.AddCommand(dnsCmd)
	rootCmd.AddCommand(httpCmd)
	rootCmd.AddCommand(sslCmd)
	rootCmd.AddCommand(nucleiCmd)
	rootCmd.AddCommand(bruteforceCmd)
	rootCmd.AddCommand(smbCmd)
	rootCmd.AddCommand(snmpCmd)
	rootCmd.AddCommand(workflowCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(versionCmd)
}

// Helper to create app context
func createAppContext() (app.Context, error) {
	cfg := app.MustLoadConfigFromViper()
	ws, err := workspace.Ensure(cfg.Workspace)
	if err != nil {
		return app.Context{}, err
	}
	return app.Context{
		Ctx:       context.Background(),
		Config:    cfg,
		Workspace: ws,
		Now:       time.Now(),
	}, nil
}

// `init` subcommand to initialize/ensure workspace structure.
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize workspace structure",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := app.MustLoadConfigFromViper()
		ws, err := workspace.Ensure(cfg.Workspace)
		if err != nil {
			return err
		}
		fmt.Printf("Workspace ready at: %s\n", ws.Root)
		return nil
	},
}

// `recon` subcommand: runs the first basic module (TCP connect probe).
var reconCmd = &cobra.Command{
	Use:   "recon",
	Short: "Run basic reconnaissance (TCP connect probe)",
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx, err := createAppContext()
		if err != nil {
			return err
		}

		target, _ := cmd.Flags().GetString("target")
		if target == "" {
			return fmt.Errorf("target is required (use --target)")
		}
		ports, _ := cmd.Flags().GetIntSlice("ports")
		if len(ports) == 0 {
			ports = []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443}
		}
		timeout := viper.GetDuration("timeout")

		reg := modules.NewRegistry()
		reg.Register(recon.New())

		runCfg := recon.RunConfig{
			Target:  target,
			Timeout: timeout,
			Ports:   ports,
		}
		return recon.Run(appCtx, runCfg)
	},
}

func init() {
	reconCmd.Flags().String("target", "", "Single target (IPv4/IPv6, hostname, or CIDR)")
	reconCmd.Flags().IntSlice("ports", nil, "Ports to scan (default: common ports)")
}

// `services` subcommand: service detection with banner grabbing
var servicesCmd = &cobra.Command{
	Use:   "services",
	Short: "Detect services on open ports (banner grabbing)",
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx, err := createAppContext()
		if err != nil {
			return err
		}

		target, _ := cmd.Flags().GetString("target")
		if target == "" {
			return fmt.Errorf("target is required (use --target)")
		}
		ports, _ := cmd.Flags().GetIntSlice("ports")
		if len(ports) == 0 {
			return fmt.Errorf("ports are required (use --ports)")
		}
		timeout := viper.GetDuration("timeout")

		runCfg := services.RunConfig{
			Target:        target,
			Ports:         ports,
			Timeout:       timeout,
			GrabBanner:    true,
			DetectVersion: true,
		}
		_, err = services.Run(appCtx, runCfg)
		return err
	},
}

func init() {
	servicesCmd.Flags().String("target", "", "Target host")
	servicesCmd.Flags().IntSlice("ports", nil, "Ports to detect services on")
}

// `dns` subcommand: DNS enumeration
var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "DNS enumeration (subdomains, zone transfer, reverse lookup)",
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx, err := createAppContext()
		if err != nil {
			return err
		}

		domain, _ := cmd.Flags().GetString("domain")
		ipRange, _ := cmd.Flags().GetString("range")
		if domain == "" && ipRange == "" {
			return fmt.Errorf("domain or range is required")
		}

		wordlist, _ := cmd.Flags().GetString("wordlist")
		bruteForce, _ := cmd.Flags().GetBool("bruteforce")
		zoneTransfer, _ := cmd.Flags().GetBool("zone-transfer")
		reverseLookup, _ := cmd.Flags().GetBool("reverse")
		timeout := viper.GetDuration("timeout")

		runCfg := dns.RunConfig{
			Domain:        domain,
			IPRange:       ipRange,
			Wordlist:      wordlist,
			BruteForce:    bruteForce,
			ZoneTransfer:  zoneTransfer,
			ReverseLookup: reverseLookup,
			Timeout:       timeout,
		}
		_, err = dns.Run(appCtx, runCfg)
		return err
	},
}

func init() {
	dnsCmd.Flags().String("domain", "", "Target domain")
	dnsCmd.Flags().String("range", "", "IP range for reverse lookup (CIDR)")
	dnsCmd.Flags().String("wordlist", "", "Path to subdomain wordlist")
	dnsCmd.Flags().Bool("bruteforce", false, "Brute-force subdomains")
	dnsCmd.Flags().Bool("zone-transfer", false, "Attempt zone transfer")
	dnsCmd.Flags().Bool("reverse", false, "Perform reverse DNS lookup")
}

// `http` subcommand: HTTP enumeration
var httpCmd = &cobra.Command{
	Use:   "http",
	Short: "HTTP enumeration (directory brute-force, tech fingerprinting)",
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx, err := createAppContext()
		if err != nil {
			return err
		}

		target, _ := cmd.Flags().GetString("target")
		if target == "" {
			return fmt.Errorf("target is required (use --target)")
		}

		wordlist, _ := cmd.Flags().GetString("wordlist")
		dirBruteForce, _ := cmd.Flags().GetBool("dir-bruteforce")
		techFingerprint, _ := cmd.Flags().GetBool("tech")
		headerAnalysis, _ := cmd.Flags().GetBool("headers")
		extensions, _ := cmd.Flags().GetStringSlice("ext")
		timeout := viper.GetDuration("timeout")

		runCfg := http.RunConfig{
			Target:          target,
			Wordlist:        wordlist,
			DirBruteForce:   dirBruteForce,
			TechFingerprint: techFingerprint,
			HeaderAnalysis:  headerAnalysis,
			Extensions:      extensions,
			Timeout:         timeout,
		}
		_, err = http.Run(appCtx, runCfg)
		return err
	},
}

func init() {
	httpCmd.Flags().String("target", "", "Target URL")
	httpCmd.Flags().String("wordlist", "", "Path to directory wordlist")
	httpCmd.Flags().Bool("dir-bruteforce", false, "Brute-force directories")
	httpCmd.Flags().Bool("tech", true, "Technology fingerprinting")
	httpCmd.Flags().Bool("headers", true, "Security header analysis")
	httpCmd.Flags().StringSlice("ext", nil, "File extensions to test (e.g., php,html,js)")
}

// `ssl` subcommand: SSL/TLS analysis
var sslCmd = &cobra.Command{
	Use:   "ssl",
	Short: "SSL/TLS analysis (certificates, ciphers, vulnerabilities)",
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx, err := createAppContext()
		if err != nil {
			return err
		}

		target, _ := cmd.Flags().GetString("target")
		if target == "" {
			return fmt.Errorf("target is required (use --target)")
		}

		port, _ := cmd.Flags().GetInt("port")
		checkAll, _ := cmd.Flags().GetBool("all")
		timeout := viper.GetDuration("timeout")

		runCfg := ssl.RunConfig{
			Target:   target,
			Port:     port,
			CheckAll: checkAll,
			Timeout:  timeout,
		}
		_, err = ssl.Run(appCtx, runCfg)
		return err
	},
}

func init() {
	sslCmd.Flags().String("target", "", "Target host")
	sslCmd.Flags().Int("port", 443, "Target port")
	sslCmd.Flags().Bool("all", false, "Check all TLS versions and ciphers")
}

// `nuclei` subcommand: Nuclei vulnerability scanner
var nucleiCmd = &cobra.Command{
	Use:   "nuclei",
	Short: "Run Nuclei vulnerability scanner",
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx, err := createAppContext()
		if err != nil {
			return err
		}

		targets, _ := cmd.Flags().GetStringSlice("target")
		targetFile, _ := cmd.Flags().GetString("target-file")
		if len(targets) == 0 && targetFile == "" {
			return fmt.Errorf("target or target-file is required")
		}

		tags, _ := cmd.Flags().GetStringSlice("tags")
		severity, _ := cmd.Flags().GetStringSlice("severity")
		templates, _ := cmd.Flags().GetStringSlice("templates")
		timeout := viper.GetDuration("timeout")

		runCfg := nuclei.RunConfig{
			Targets:      targets,
			TargetFile:   targetFile,
			TemplateTags: tags,
			Severity:     severity,
			Templates:    templates,
			Timeout:      timeout,
		}
		_, err = nuclei.Run(appCtx, runCfg)
		return err
	},
}

func init() {
	nucleiCmd.Flags().StringSlice("target", nil, "Target URLs")
	nucleiCmd.Flags().String("target-file", "", "File containing targets")
	nucleiCmd.Flags().StringSlice("tags", nil, "Template tags (cve, rce, sqli, etc.)")
	nucleiCmd.Flags().StringSlice("severity", nil, "Severity filter (info, low, medium, high, critical)")
	nucleiCmd.Flags().StringSlice("templates", nil, "Specific templates to run")
}

// `bruteforce` subcommand: Authentication testing
var bruteforceCmd = &cobra.Command{
	Use:   "bruteforce",
	Short: "Authentication testing (brute-force, password spraying)",
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx, err := createAppContext()
		if err != nil {
			return err
		}

		target, _ := cmd.Flags().GetString("target")
		if target == "" {
			return fmt.Errorf("target is required (use --target)")
		}

		protocol, _ := cmd.Flags().GetString("protocol")
		port, _ := cmd.Flags().GetInt("port")
		userFile, _ := cmd.Flags().GetString("users")
		passFile, _ := cmd.Flags().GetString("passwords")
		user, _ := cmd.Flags().GetString("user")
		pass, _ := cmd.Flags().GetString("password")
		spray, _ := cmd.Flags().GetBool("spray")
		stopOnSuccess, _ := cmd.Flags().GetBool("stop-on-success")
		timeout := viper.GetDuration("timeout")

		runCfg := bruteforce.RunConfig{
			Target:        target,
			Port:          port,
			Protocol:      protocol,
			UserFile:      userFile,
			PassFile:      passFile,
			SingleUser:    user,
			SinglePass:    pass,
			PasswordSpray: spray,
			StopOnSuccess: stopOnSuccess,
			Timeout:       timeout,
		}
		_, err = bruteforce.Run(appCtx, runCfg)
		return err
	},
}

func init() {
	bruteforceCmd.Flags().String("target", "", "Target host")
	bruteforceCmd.Flags().String("protocol", "http", "Protocol (http, https, ssh, ftp, mysql, postgres, redis, smb)")
	bruteforceCmd.Flags().Int("port", 0, "Target port (default: protocol default)")
	bruteforceCmd.Flags().String("users", "", "File containing usernames")
	bruteforceCmd.Flags().String("passwords", "", "File containing passwords")
	bruteforceCmd.Flags().String("user", "", "Single username")
	bruteforceCmd.Flags().String("password", "", "Single password")
	bruteforceCmd.Flags().Bool("spray", false, "Password spray mode")
	bruteforceCmd.Flags().Bool("stop-on-success", false, "Stop after first success")
}

// `smb` subcommand: SMB enumeration
var smbCmd = &cobra.Command{
	Use:   "smb",
	Short: "SMB/NetBIOS enumeration (shares, users, OS detection)",
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx, err := createAppContext()
		if err != nil {
			return err
		}

		target, _ := cmd.Flags().GetString("target")
		if target == "" {
			return fmt.Errorf("target is required (use --target)")
		}

		port, _ := cmd.Flags().GetInt("port")
		nullSession, _ := cmd.Flags().GetBool("null-session")
		enumShares, _ := cmd.Flags().GetBool("shares")
		checkVulns, _ := cmd.Flags().GetBool("vulns")
		timeout := viper.GetDuration("timeout")

		runCfg := smb.RunConfig{
			Target:      target,
			Port:        port,
			NullSession: nullSession,
			EnumShares:  enumShares,
			CheckVulns:  checkVulns,
			Timeout:     timeout,
		}
		_, err = smb.Run(appCtx, runCfg)
		return err
	},
}

func init() {
	smbCmd.Flags().String("target", "", "Target host")
	smbCmd.Flags().Int("port", 445, "Target port")
	smbCmd.Flags().Bool("null-session", true, "Test null session")
	smbCmd.Flags().Bool("shares", true, "Enumerate shares")
	smbCmd.Flags().Bool("vulns", true, "Check for vulnerabilities")
}

// `snmp` subcommand: SNMP enumeration
var snmpCmd = &cobra.Command{
	Use:   "snmp",
	Short: "SNMP enumeration (community strings, system info)",
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx, err := createAppContext()
		if err != nil {
			return err
		}

		target, _ := cmd.Flags().GetString("target")
		if target == "" {
			return fmt.Errorf("target is required (use --target)")
		}

		port, _ := cmd.Flags().GetInt("port")
		community, _ := cmd.Flags().GetString("community")
		communityFile, _ := cmd.Flags().GetString("community-file")
		walk, _ := cmd.Flags().GetBool("walk")
		timeout := viper.GetDuration("timeout")

		var communities []string
		if community != "" {
			communities = []string{community}
		}

		runCfg := snmp.RunConfig{
			Target:        target,
			Port:          port,
			Communities:   communities,
			CommunityFile: communityFile,
			WalkOIDs:      walk,
			Timeout:       timeout,
		}
		_, err = snmp.Run(appCtx, runCfg)
		return err
	},
}

func init() {
	snmpCmd.Flags().String("target", "", "Target host")
	snmpCmd.Flags().Int("port", 161, "Target port")
	snmpCmd.Flags().String("community", "", "Community string to test")
	snmpCmd.Flags().String("community-file", "", "File containing community strings")
	snmpCmd.Flags().Bool("walk", false, "Walk OIDs for detailed info")
}

// `workflow` subcommand: Workflow execution
var workflowCmd = &cobra.Command{
	Use:   "workflow",
	Short: "Execute or manage workflows",
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var workflowRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a workflow",
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx, err := createAppContext()
		if err != nil {
			return err
		}

		name, _ := cmd.Flags().GetString("name")
		file, _ := cmd.Flags().GetString("file")
		target, _ := cmd.Flags().GetString("target")

		var wf *workflow.Workflow

		if file != "" {
			wf, err = workflow.LoadWorkflow(file)
			if err != nil {
				return fmt.Errorf("failed to load workflow: %w", err)
			}
		} else if name != "" {
			var ok bool
			wf, ok = workflow.GetPredefinedWorkflow(name)
			if !ok {
				return fmt.Errorf("unknown workflow: %s (available: %s)", name, strings.Join(workflow.ListPredefinedWorkflows(), ", "))
			}
		} else {
			return fmt.Errorf("workflow name or file is required")
		}

		overrides := make(map[string]interface{})
		if target != "" {
			overrides["target"] = target
		}

		_, err = workflow.Execute(appCtx, wf, overrides)
		return err
	},
}

var workflowListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available predefined workflows",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Available workflows:")
		for _, name := range workflow.ListPredefinedWorkflows() {
			if wf, ok := workflow.GetPredefinedWorkflow(name); ok {
				fmt.Printf("  %s - %s\n", name, wf.Description)
			}
		}
	},
}

func init() {
	workflowRunCmd.Flags().String("name", "", "Predefined workflow name")
	workflowRunCmd.Flags().String("file", "", "Path to workflow YAML file")
	workflowRunCmd.Flags().String("target", "", "Target to scan")

	workflowCmd.AddCommand(workflowRunCmd)
	workflowCmd.AddCommand(workflowListCmd)
}

// `report` subcommand: Generate reports from workspace data
var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate comprehensive report from workspace findings",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := app.MustLoadConfigFromViper()
		ws, err := workspace.Ensure(cfg.Workspace)
		if err != nil {
			return err
		}

		format, _ := cmd.Flags().GetString("format")
		output, _ := cmd.Flags().GetString("output")
		title, _ := cmd.Flags().GetString("title")
		diagram, _ := cmd.Flags().GetBool("diagram")

		// Collect all findings from workspace
		collector := reports.NewCollector(ws)
		report, err := collector.CollectAll()
		if err != nil {
			return fmt.Errorf("failed to collect findings: %w", err)
		}

		if title != "" {
			report.Title = title
		}

		timestamp := time.Now().Format("20060102-150405")

		// Generate network diagram if requested
		var netDiagram *reports.NetworkDiagram
		if diagram {
			netDiagram = reports.BuildNetworkDiagram(report.Findings)
			// Add SVG to report for HTML output
			svgContent := netDiagram.GenerateSVG()
			if svgContent != "" {
				// Remove XML declaration for embedding in HTML
				if idx := strings.Index(svgContent, "<svg"); idx > 0 {
					svgContent = svgContent[idx:]
				}
				report.NetworkDiagramSVG = svgContent
			}
		}

		// Determine output path
		if output == "" {
			switch format {
			case "json":
				output = filepath.Join(ws.Root, "reports", fmt.Sprintf("report-%s.json", timestamp))
			case "html":
				output = filepath.Join(ws.Root, "reports", fmt.Sprintf("report-%s.html", timestamp))
			default:
				output = filepath.Join(ws.Root, "reports", fmt.Sprintf("report-%s.md", timestamp))
			}
		}

		// Export report
		switch format {
		case "json":
			if err := report.ExportJSON(output); err != nil {
				return err
			}
		case "html":
			if err := report.ExportHTML(output); err != nil {
				return err
			}
		default:
			if err := report.ExportMarkdown(output); err != nil {
				return err
			}
		}

		fmt.Printf("[+] Report generated: %s\n", output)
		fmt.Printf("    Total findings: %d\n", report.Statistics.TotalFindings)
		fmt.Printf("    Critical: %d, High: %d, Medium: %d, Low: %d, Info: %d\n",
			report.Statistics.FindingsBySeverity["critical"],
			report.Statistics.FindingsBySeverity["high"],
			report.Statistics.FindingsBySeverity["medium"],
			report.Statistics.FindingsBySeverity["low"],
			report.Statistics.FindingsBySeverity["info"])

		// Also save standalone SVG and print ASCII diagram
		if diagram && netDiagram != nil {
			svgPath := filepath.Join(ws.Root, "reports", fmt.Sprintf("network-%s.svg", timestamp))
			svgContent := netDiagram.GenerateSVG()
			if svgContent != "" {
				if err := os.MkdirAll(filepath.Dir(svgPath), 0o755); err == nil {
					if err := os.WriteFile(svgPath, []byte(svgContent), 0o644); err == nil {
						fmt.Printf("[+] Network diagram (SVG): %s\n", svgPath)
					}
				}
			}
			// Print ASCII diagram to console
			fmt.Println(netDiagram.GenerateASCII())
		}

		return nil
	},
}

func init() {
	reportCmd.Flags().String("format", "md", "Output format (md, html, json)")
	reportCmd.Flags().String("output", "", "Output file path (default: workspace/reports/)")
	reportCmd.Flags().String("title", "", "Report title")
	reportCmd.Flags().Bool("diagram", false, "Generate network topology diagram")
}

// `version` subcommand.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version.String())
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
