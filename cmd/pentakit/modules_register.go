package pentakit

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/tldr-it-stepankutaj/pentakit/internal/app"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/bruteforce"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/dns"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/http"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/nuclei"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/recon"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/services"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/smb"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/snmp"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/ssl"
	"github.com/tldr-it-stepankutaj/pentakit/internal/workflow"
)

// registerWorkflowModules wires every CLI module into the workflow engine's
// generic ModuleRunner registry. Without this, workflow.RegisterModule is
// never called anywhere, the registry stays empty, and `workflow run` fails
// every single step with "unknown module: <name>" — including all three
// predefined workflows (quick-recon, web-assessment, full-assessment) and
// any custom YAML workflow. Config keys below match the snake_case names
// already used by PredefinedWorkflows and the README's example YAML, so
// existing workflow definitions work unchanged once a real adapter exists.
func registerWorkflowModules() {
	withCtx := func(appCtx app.Context, ctx context.Context) app.Context {
		appCtx.Ctx = ctx
		return appCtx
	}

	workflow.RegisterModule("recon", func(ctx context.Context, appCtx app.Context, cfg map[string]interface{}) (interface{}, error) {
		runCfg := recon.RunConfig{
			Target:  cfgString(cfg, "target", ""),
			Ports:   cfgPorts(cfg, "ports"),
			Timeout: cfgDuration(cfg, "timeout", appCtx.Config.Timeout),
		}
		// recon.Run reports findings via stdout/JSONL/markdown as a side
		// effect and returns no result value, so there is nothing to hand
		// back as `output` here beyond the error.
		err := recon.Run(withCtx(appCtx, ctx), runCfg)
		return nil, err
	})

	workflow.RegisterModule("services", func(ctx context.Context, appCtx app.Context, cfg map[string]interface{}) (interface{}, error) {
		runCfg := services.RunConfig{
			Target:        cfgString(cfg, "target", ""),
			Ports:         cfgPorts(cfg, "ports"),
			Timeout:       cfgDuration(cfg, "timeout", appCtx.Config.Timeout),
			GrabBanner:    cfgBool(cfg, "grab_banner", true),
			DetectVersion: cfgBool(cfg, "detect_version", true),
		}
		return services.Run(withCtx(appCtx, ctx), runCfg)
	})

	workflow.RegisterModule("dns", func(ctx context.Context, appCtx app.Context, cfg map[string]interface{}) (interface{}, error) {
		domain := cfgString(cfg, "domain", cfgString(cfg, "target", ""))
		runCfg := dns.RunConfig{
			Domain:        domain,
			IPRange:       cfgString(cfg, "range", ""),
			Wordlist:      cfgString(cfg, "wordlist", ""),
			Timeout:       cfgDuration(cfg, "timeout", appCtx.Config.Timeout),
			ZoneTransfer:  cfgBool(cfg, "zone_transfer", false),
			ReverseLookup: cfgBool(cfg, "reverse", false),
			BruteForce:    cfgBool(cfg, "bruteforce", false),
			CTLogs:        cfgBool(cfg, "ct_logs", false),
		}
		return dns.Run(withCtx(appCtx, ctx), runCfg)
	})

	workflow.RegisterModule("http", func(ctx context.Context, appCtx app.Context, cfg map[string]interface{}) (interface{}, error) {
		runCfg := http.RunConfig{
			Target:          cfgString(cfg, "target", ""),
			Wordlist:        cfgString(cfg, "wordlist", ""),
			Timeout:         cfgDuration(cfg, "timeout", appCtx.Config.Timeout),
			Extensions:      cfgStringSlice(cfg, "ext", "extensions"),
			TechFingerprint: cfgBool(cfg, "tech_fingerprint", true),
			HeaderAnalysis:  cfgBool(cfg, "header_analysis", true),
			DirBruteForce:   cfgBool(cfg, "dir_bruteforce", false),
			FollowRedirects: cfgBool(cfg, "follow_redirects", false),
		}
		return http.Run(withCtx(appCtx, ctx), runCfg)
	})

	workflow.RegisterModule("ssl", func(ctx context.Context, appCtx app.Context, cfg map[string]interface{}) (interface{}, error) {
		runCfg := ssl.RunConfig{
			Target:   cfgString(cfg, "target", ""),
			Port:     cfgInt(cfg, "port", 443),
			Timeout:  cfgDuration(cfg, "timeout", appCtx.Config.Timeout),
			CheckAll: cfgBool(cfg, "all", false),
		}
		return ssl.Run(withCtx(appCtx, ctx), runCfg)
	})

	workflow.RegisterModule("nuclei", func(ctx context.Context, appCtx app.Context, cfg map[string]interface{}) (interface{}, error) {
		var targets []string
		if t := cfgString(cfg, "target", ""); t != "" {
			targets = []string{t}
		}
		targets = append(targets, cfgStringSlice(cfg, "targets", "")...)
		runCfg := nuclei.RunConfig{
			Targets:      targets,
			TargetFile:   cfgString(cfg, "target_file", ""),
			Templates:    cfgStringSlice(cfg, "templates", ""),
			TemplateTags: cfgStringSlice(cfg, "template_tags", "tags"),
			Severity:     cfgStringSlice(cfg, "severity", ""),
			Timeout:      cfgDuration(cfg, "timeout", 30*time.Minute),
		}
		return nuclei.Run(withCtx(appCtx, ctx), runCfg)
	})

	workflow.RegisterModule("bruteforce", func(ctx context.Context, appCtx app.Context, cfg map[string]interface{}) (interface{}, error) {
		target := cfgString(cfg, "target", "")
		port := cfgInt(cfg, "port", 0)
		protocol := cfgString(cfg, "protocol", "http")

		if cfgBool(cfg, "default_only", false) {
			return bruteforce.TestDefaultCredentials(withCtx(appCtx, ctx), target, port, protocol)
		}

		runCfg := bruteforce.RunConfig{
			Target:        target,
			Port:          port,
			Protocol:      protocol,
			UserFile:      cfgString(cfg, "user_file", cfgString(cfg, "users", "")),
			PassFile:      cfgString(cfg, "pass_file", cfgString(cfg, "passwords", "")),
			SingleUser:    cfgString(cfg, "user", ""),
			SinglePass:    cfgString(cfg, "password", ""),
			PasswordSpray: cfgBool(cfg, "spray", false),
			StopOnSuccess: cfgBool(cfg, "stop_on_success", false),
			Timeout:       cfgDuration(cfg, "timeout", appCtx.Config.Timeout),
		}
		return bruteforce.Run(withCtx(appCtx, ctx), runCfg)
	})

	workflow.RegisterModule("smb", func(ctx context.Context, appCtx app.Context, cfg map[string]interface{}) (interface{}, error) {
		runCfg := smb.RunConfig{
			Target:      cfgString(cfg, "target", ""),
			Port:        cfgInt(cfg, "port", 445),
			Timeout:     cfgDuration(cfg, "timeout", appCtx.Config.Timeout),
			NullSession: cfgBool(cfg, "null_session", true),
			EnumShares:  cfgBool(cfg, "shares", true),
			CheckVulns:  cfgBool(cfg, "vulns", true),
		}
		return smb.Run(withCtx(appCtx, ctx), runCfg)
	})

	workflow.RegisterModule("snmp", func(ctx context.Context, appCtx app.Context, cfg map[string]interface{}) (interface{}, error) {
		var communities []string
		if c := cfgString(cfg, "community", ""); c != "" {
			communities = []string{c}
		}
		runCfg := snmp.RunConfig{
			Target:        cfgString(cfg, "target", ""),
			Port:          cfgInt(cfg, "port", 161),
			Timeout:       cfgDuration(cfg, "timeout", appCtx.Config.Timeout),
			Communities:   communities,
			CommunityFile: cfgString(cfg, "community_file", ""),
			WalkOIDs:      cfgBool(cfg, "walk", false),
		}
		return snmp.Run(withCtx(appCtx, ctx), runCfg)
	})
}

// --- generic map[string]interface{} -> typed value helpers ---
//
// Workflow step config comes from two places that disagree on numeric/slice
// representation: Go literals in PredefinedWorkflows (e.g. []int{80, 443})
// and YAML-decoded values from a user's workflow file (gopkg.in/yaml.v3
// decodes YAML sequences into []interface{} and YAML integers into int,
// unlike encoding/json which would use float64). These helpers accept both.

func cfgString(cfg map[string]interface{}, key, def string) string {
	if v, ok := cfg[key]; ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return def
}

func cfgBool(cfg map[string]interface{}, key string, def bool) bool {
	if v, ok := cfg[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return def
}

func cfgInt(cfg map[string]interface{}, key string, def int) int {
	if v, ok := cfg[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case float64:
			return int(n)
		case string:
			if parsed, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
				return parsed
			}
		}
	}
	return def
}

func cfgDuration(cfg map[string]interface{}, key string, def time.Duration) time.Duration {
	if v, ok := cfg[key]; ok {
		if s, ok := v.(string); ok {
			if d, err := time.ParseDuration(s); err == nil {
				return d
			}
		}
	}
	return def
}

// cfgStringSlice reads `key`, falling back to `altKey` (pass "" to skip),
// accepting both a native []string (Go literal) and a []interface{} of
// strings (YAML/JSON decoded).
func cfgStringSlice(cfg map[string]interface{}, key, altKey string) []string {
	if out := stringSliceFrom(cfg[key]); out != nil {
		return out
	}
	if altKey != "" {
		return stringSliceFrom(cfg[altKey])
	}
	return nil
}

func stringSliceFrom(v interface{}) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []interface{}:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

// cfgPorts reads a port list given as a native []int (Go literal), a
// []interface{} of numbers (YAML/JSON decoded), or a string such as
// "1-1000" or "22,80,443,1000-2000" (as used by the full-assessment
// predefined workflow and documented for the `recon --ports` CLI flag).
func cfgPorts(cfg map[string]interface{}, key string) []int {
	v, ok := cfg[key]
	if !ok {
		return nil
	}
	switch s := v.(type) {
	case []int:
		return s
	case []interface{}:
		out := make([]int, 0, len(s))
		for _, item := range s {
			switch n := item.(type) {
			case int:
				out = append(out, n)
			case float64:
				out = append(out, int(n))
			}
		}
		return out
	case string:
		return parsePortSpec(s)
	}
	return nil
}

func parsePortSpec(spec string) []int {
	var ports []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			start, err1 := strconv.Atoi(strings.TrimSpace(lo))
			end, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || start > end {
				continue
			}
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
			continue
		}
		if p, err := strconv.Atoi(part); err == nil {
			ports = append(ports, p)
		}
	}
	return ports
}
