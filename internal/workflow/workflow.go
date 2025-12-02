package workflow

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tldr-it-stepankutaj/pentakit/internal/app"
)

// Workflow represents a pentest workflow definition.
type Workflow struct {
	Name        string            `yaml:"name" json:"name"`
	Description string            `yaml:"description,omitempty" json:"description,omitempty"`
	Author      string            `yaml:"author,omitempty" json:"author,omitempty"`
	Version     string            `yaml:"version,omitempty" json:"version,omitempty"`
	Variables   map[string]string `yaml:"variables,omitempty" json:"variables,omitempty"`
	Steps       []Step            `yaml:"steps" json:"steps"`
}

// Step represents a single workflow step.
type Step struct {
	ID          string                 `yaml:"id,omitempty" json:"id,omitempty"`
	Name        string                 `yaml:"name" json:"name"`
	Module      string                 `yaml:"module" json:"module"`
	Description string                 `yaml:"description,omitempty" json:"description,omitempty"`
	Config      map[string]interface{} `yaml:"config,omitempty" json:"config,omitempty"`
	DependsOn   []string               `yaml:"depends_on,omitempty" json:"depends_on,omitempty"`
	Condition   string                 `yaml:"condition,omitempty" json:"condition,omitempty"`   // e.g., "previous.found_count > 0"
	OnFailure   string                 `yaml:"on_failure,omitempty" json:"on_failure,omitempty"` // continue, stop, skip
	Timeout     string                 `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Retries     int                    `yaml:"retries,omitempty" json:"retries,omitempty"`
	Parallel    bool                   `yaml:"parallel,omitempty" json:"parallel,omitempty"`
}

// ExecutionContext holds the execution state.
type ExecutionContext struct {
	AppCtx      app.Context
	Workflow    *Workflow
	Variables   map[string]interface{}
	StepResults map[string]*StepResult
	StartTime   time.Time
	mu          sync.RWMutex
}

// StepResult holds the result of a step execution.
type StepResult struct {
	StepID     string        `json:"step_id"`
	StepName   string        `json:"step_name"`
	Module     string        `json:"module"`
	Status     string        `json:"status"` // pending, running, completed, failed, skipped
	StartTime  time.Time     `json:"start_time"`
	EndTime    time.Time     `json:"end_time"`
	Duration   time.Duration `json:"duration"`
	Output     interface{}   `json:"output,omitempty"`
	Error      string        `json:"error,omitempty"`
	FoundCount int           `json:"found_count"`
}

// ModuleRunner is a function type for running modules.
type ModuleRunner func(ctx context.Context, appCtx app.Context, config map[string]interface{}) (interface{}, error)

// ModuleRegistry holds registered module runners.
var moduleRunners = make(map[string]ModuleRunner)

// RegisterModule registers a module runner.
func RegisterModule(name string, runner ModuleRunner) {
	moduleRunners[name] = runner
}

// LoadWorkflow loads a workflow from a YAML file.
func LoadWorkflow(path string) (*Workflow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read workflow file: %w", err)
	}

	var workflow Workflow
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		return nil, fmt.Errorf("failed to parse workflow: %w", err)
	}

	// Assign IDs to steps if not provided
	for i := range workflow.Steps {
		if workflow.Steps[i].ID == "" {
			workflow.Steps[i].ID = fmt.Sprintf("step_%d", i+1)
		}
	}

	return &workflow, nil
}

// SaveWorkflow saves a workflow to a YAML file.
func SaveWorkflow(workflow *Workflow, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	data, err := yaml.Marshal(workflow)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o644)
}

// Execute runs a workflow.
func Execute(ctx app.Context, workflow *Workflow, overrides map[string]interface{}) (*ExecutionReport, error) {
	execCtx := &ExecutionContext{
		AppCtx:      ctx,
		Workflow:    workflow,
		Variables:   make(map[string]interface{}),
		StepResults: make(map[string]*StepResult),
		StartTime:   time.Now(),
	}

	// Initialize variables
	for k, v := range workflow.Variables {
		execCtx.Variables[k] = v
	}
	for k, v := range overrides {
		execCtx.Variables[k] = v
	}

	fmt.Printf("\n╔══════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║  Workflow: %-50s║\n", workflow.Name)
	fmt.Printf("║  Steps: %-52d║\n", len(workflow.Steps))
	fmt.Printf("╚══════════════════════════════════════════════════════════════╝\n\n")

	// Build dependency graph (for future cycle detection)
	_ = buildDependencyGraph(workflow.Steps)

	// Execute steps respecting dependencies
	completed := make(map[string]bool)
	var executionOrder []string

	for len(completed) < len(workflow.Steps) {
		// Find steps that can run (all dependencies satisfied)
		var runnable []Step
		for _, step := range workflow.Steps {
			if completed[step.ID] {
				continue
			}
			canRun := true
			for _, dep := range step.DependsOn {
				if !completed[dep] {
					canRun = false
					break
				}
			}
			if canRun {
				runnable = append(runnable, step)
			}
		}

		if len(runnable) == 0 {
			return nil, fmt.Errorf("workflow deadlock: circular dependency detected")
		}

		// Execute runnable steps
		if len(runnable) == 1 || !runnable[0].Parallel {
			// Sequential execution
			for _, step := range runnable {
				result := executeStep(execCtx, step)
				completed[step.ID] = true
				executionOrder = append(executionOrder, step.ID)

				if result.Status == "failed" && step.OnFailure != "continue" {
					if step.OnFailure == "stop" || step.OnFailure == "" {
						return generateReport(execCtx, executionOrder), fmt.Errorf("step %s failed: %s", step.ID, result.Error)
					}
				}
			}
		} else {
			// Parallel execution for steps that can run together
			var wg sync.WaitGroup
			for _, step := range runnable {
				if step.Parallel {
					step := step
					wg.Add(1)
					go func() {
						defer wg.Done()
						executeStep(execCtx, step)
					}()
				} else {
					executeStep(execCtx, step)
				}
				completed[step.ID] = true
				executionOrder = append(executionOrder, step.ID)
			}
			wg.Wait()
		}
	}

	report := generateReport(execCtx, executionOrder)

	// Save report
	timestamp := ctx.Now.Format("20060102-150405")
	reportPath := ctx.Workspace.Path("reports", fmt.Sprintf("workflow-%s-%s.json", sanitizeFilename(workflow.Name), timestamp))
	if err := saveReport(report, reportPath); err != nil {
		fmt.Printf("[!] Failed to save report: %v\n", err)
	}

	return report, nil
}

func executeStep(execCtx *ExecutionContext, step Step) *StepResult {
	result := &StepResult{
		StepID:    step.ID,
		StepName:  step.Name,
		Module:    step.Module,
		Status:    "running",
		StartTime: time.Now(),
	}

	execCtx.mu.Lock()
	execCtx.StepResults[step.ID] = result
	execCtx.mu.Unlock()

	fmt.Printf("┌─ Step: %s (%s)\n", step.Name, step.Module)
	fmt.Printf("│  Status: Running...\n")

	// Check condition
	if step.Condition != "" {
		if !evaluateCondition(execCtx, step.Condition) {
			result.Status = "skipped"
			result.EndTime = time.Now()
			result.Duration = result.EndTime.Sub(result.StartTime)
			fmt.Printf("│  Status: Skipped (condition not met)\n")
			fmt.Printf("└─────────────────────────────────────────\n\n")
			return result
		}
	}

	// Parse timeout
	timeout := 30 * time.Minute
	if step.Timeout != "" {
		if d, err := time.ParseDuration(step.Timeout); err == nil {
			timeout = d
		}
	}

	// Resolve config variables
	config := resolveConfig(execCtx, step.Config)

	// Execute with retries
	var output interface{}
	var err error
	attempts := step.Retries + 1
	if attempts < 1 {
		attempts = 1
	}

	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			fmt.Printf("│  Retry attempt %d/%d\n", attempt, attempts)
		}

		ctx, cancel := context.WithTimeout(execCtx.AppCtx.Ctx, timeout)
		output, err = runModule(ctx, execCtx.AppCtx, step.Module, config)
		cancel()

		if err == nil {
			break
		}

		if attempt < attempts {
			time.Sleep(time.Second * time.Duration(attempt))
		}
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		fmt.Printf("│  Status: Failed - %s\n", err)
	} else {
		result.Status = "completed"
		result.Output = output
		result.FoundCount = countFindings(output)
		fmt.Printf("│  Status: Completed (found: %d, duration: %s)\n", result.FoundCount, result.Duration.Round(time.Millisecond))
	}

	fmt.Printf("└─────────────────────────────────────────\n\n")

	return result
}

func runModule(ctx context.Context, appCtx app.Context, moduleName string, config map[string]interface{}) (interface{}, error) {
	runner, ok := moduleRunners[moduleName]
	if !ok {
		return nil, fmt.Errorf("unknown module: %s", moduleName)
	}

	return runner(ctx, appCtx, config)
}

func resolveConfig(execCtx *ExecutionContext, config map[string]interface{}) map[string]interface{} {
	resolved := make(map[string]interface{})
	for k, v := range config {
		resolved[k] = resolveValue(execCtx, v)
	}
	return resolved
}

func resolveValue(execCtx *ExecutionContext, value interface{}) interface{} {
	switch v := value.(type) {
	case string:
		// Check for variable references like ${variable}
		if strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") {
			varName := v[2 : len(v)-1]
			if val, ok := execCtx.Variables[varName]; ok {
				return val
			}
			// Check step results
			parts := strings.Split(varName, ".")
			if len(parts) == 2 {
				if result, ok := execCtx.StepResults[parts[0]]; ok {
					switch parts[1] {
					case "output":
						return result.Output
					case "found_count":
						return result.FoundCount
					}
				}
			}
		}
		return v
	case map[string]interface{}:
		return resolveConfig(execCtx, v)
	case []interface{}:
		resolved := make([]interface{}, len(v))
		for i, item := range v {
			resolved[i] = resolveValue(execCtx, item)
		}
		return resolved
	default:
		return v
	}
}

func evaluateCondition(execCtx *ExecutionContext, condition string) bool {
	// Simple condition evaluation
	// Supports: step_id.found_count > 0, step_id.status == "completed"

	parts := strings.Fields(condition)
	if len(parts) != 3 {
		return true // Invalid condition, assume true
	}

	leftParts := strings.Split(parts[0], ".")
	if len(leftParts) != 2 {
		return true
	}

	stepID, field := leftParts[0], leftParts[1]
	operator := parts[1]
	rightValue := strings.Trim(parts[2], "\"'")

	execCtx.mu.RLock()
	result, ok := execCtx.StepResults[stepID]
	execCtx.mu.RUnlock()

	if !ok {
		return false
	}

	var leftValue interface{}
	switch field {
	case "found_count":
		leftValue = result.FoundCount
	case "status":
		leftValue = result.Status
	default:
		return true
	}

	switch operator {
	case "==":
		return fmt.Sprintf("%v", leftValue) == rightValue
	case "!=":
		return fmt.Sprintf("%v", leftValue) != rightValue
	case ">":
		if lv, ok := leftValue.(int); ok {
			var rv int
			fmt.Sscanf(rightValue, "%d", &rv)
			return lv > rv
		}
	case ">=":
		if lv, ok := leftValue.(int); ok {
			var rv int
			fmt.Sscanf(rightValue, "%d", &rv)
			return lv >= rv
		}
	case "<":
		if lv, ok := leftValue.(int); ok {
			var rv int
			fmt.Sscanf(rightValue, "%d", &rv)
			return lv < rv
		}
	case "<=":
		if lv, ok := leftValue.(int); ok {
			var rv int
			fmt.Sscanf(rightValue, "%d", &rv)
			return lv <= rv
		}
	}

	return true
}

func buildDependencyGraph(steps []Step) map[string][]string {
	graph := make(map[string][]string)
	for _, step := range steps {
		graph[step.ID] = step.DependsOn
	}
	return graph
}

func countFindings(output interface{}) int {
	switch v := output.(type) {
	case []interface{}:
		return len(v)
	case map[string]interface{}:
		if count, ok := v["count"].(int); ok {
			return count
		}
		return 1
	case int:
		return v
	default:
		return 0
	}
}

// ExecutionReport represents a workflow execution report.
type ExecutionReport struct {
	Workflow       string                 `json:"workflow"`
	StartTime      time.Time              `json:"start_time"`
	EndTime        time.Time              `json:"end_time"`
	Duration       time.Duration          `json:"duration"`
	Status         string                 `json:"status"`
	TotalSteps     int                    `json:"total_steps"`
	CompletedSteps int                    `json:"completed_steps"`
	FailedSteps    int                    `json:"failed_steps"`
	SkippedSteps   int                    `json:"skipped_steps"`
	TotalFindings  int                    `json:"total_findings"`
	StepResults    map[string]*StepResult `json:"step_results"`
	ExecutionOrder []string               `json:"execution_order"`
}

func generateReport(execCtx *ExecutionContext, executionOrder []string) *ExecutionReport {
	report := &ExecutionReport{
		Workflow:       execCtx.Workflow.Name,
		StartTime:      execCtx.StartTime,
		EndTime:        time.Now(),
		TotalSteps:     len(execCtx.Workflow.Steps),
		StepResults:    execCtx.StepResults,
		ExecutionOrder: executionOrder,
	}
	report.Duration = report.EndTime.Sub(report.StartTime)

	report.Status = "completed"
	for _, result := range execCtx.StepResults {
		switch result.Status {
		case "completed":
			report.CompletedSteps++
		case "failed":
			report.FailedSteps++
			report.Status = "partial"
		case "skipped":
			report.SkippedSteps++
		}
		report.TotalFindings += result.FoundCount
	}

	if report.FailedSteps > 0 && report.CompletedSteps == 0 {
		report.Status = "failed"
	}

	return report
}

func saveReport(report *ExecutionReport, path string) error {
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
	if err := enc.Encode(report); err != nil {
		return err
	}
	return w.Flush()
}

func sanitizeFilename(name string) string {
	replacer := strings.NewReplacer(" ", "-", "/", "-", "\\", "-", ":", "-")
	return strings.ToLower(replacer.Replace(name))
}

// PredefinedWorkflows contains common workflow templates.
var PredefinedWorkflows = map[string]*Workflow{
	"quick-recon": {
		Name:        "Quick Reconnaissance",
		Description: "Fast reconnaissance workflow for initial target assessment",
		Steps: []Step{
			{ID: "recon", Name: "Port Scan", Module: "recon", Config: map[string]interface{}{
				"ports": []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443},
			}},
			{ID: "services", Name: "Service Detection", Module: "services", DependsOn: []string{"recon"}, Config: map[string]interface{}{
				"grab_banner": true,
			}},
			{ID: "http", Name: "HTTP Analysis", Module: "http", DependsOn: []string{"services"}, Condition: "services.found_count > 0", Config: map[string]interface{}{
				"tech_fingerprint": true,
				"header_analysis":  true,
			}},
		},
	},
	"web-assessment": {
		Name:        "Web Application Assessment",
		Description: "Comprehensive web application security assessment",
		Steps: []Step{
			{ID: "http", Name: "HTTP Enumeration", Module: "http", Config: map[string]interface{}{
				"dir_bruteforce":   true,
				"tech_fingerprint": true,
				"header_analysis":  true,
			}},
			{ID: "ssl", Name: "SSL/TLS Analysis", Module: "ssl", Parallel: true},
			{ID: "nuclei", Name: "Vulnerability Scan", Module: "nuclei", DependsOn: []string{"http"}, Config: map[string]interface{}{
				"template_tags": []string{"cve", "exposure", "misconfiguration"},
				"severity":      []string{"medium", "high", "critical"},
			}},
		},
	},
	"full-assessment": {
		Name:        "Full Infrastructure Assessment",
		Description: "Complete infrastructure security assessment workflow",
		Steps: []Step{
			{ID: "recon", Name: "Port Scan", Module: "recon", Config: map[string]interface{}{
				"ports": "1-1000",
			}},
			{ID: "services", Name: "Service Detection", Module: "services", DependsOn: []string{"recon"}},
			{ID: "dns", Name: "DNS Enumeration", Module: "dns", Parallel: true, Config: map[string]interface{}{
				"bruteforce":    true,
				"zone_transfer": true,
			}},
			{ID: "http", Name: "HTTP Analysis", Module: "http", DependsOn: []string{"services"}},
			{ID: "ssl", Name: "SSL/TLS Analysis", Module: "ssl", DependsOn: []string{"services"}},
			{ID: "smb", Name: "SMB Enumeration", Module: "smb", DependsOn: []string{"services"}, Condition: "services.found_count > 0"},
			{ID: "snmp", Name: "SNMP Enumeration", Module: "snmp", DependsOn: []string{"services"}},
			{ID: "nuclei", Name: "Vulnerability Scan", Module: "nuclei", DependsOn: []string{"http", "ssl"}},
			{ID: "bruteforce", Name: "Default Credentials", Module: "bruteforce", DependsOn: []string{"services"}, Config: map[string]interface{}{
				"default_only": true,
			}},
		},
	},
}

// GetPredefinedWorkflow returns a predefined workflow by name.
func GetPredefinedWorkflow(name string) (*Workflow, bool) {
	wf, ok := PredefinedWorkflows[name]
	return wf, ok
}

// ListPredefinedWorkflows returns a list of available predefined workflows.
func ListPredefinedWorkflows() []string {
	var names []string
	for name := range PredefinedWorkflows {
		names = append(names, name)
	}
	return names
}
