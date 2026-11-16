package workflow

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/tldr-it-stepankutaj/pentakit/internal/app"
)

// testWorkspace is a minimal app.WorkspaceHandle backed by a temp directory,
// so Execute's report-saving side effect has somewhere real to write.
type testWorkspace struct{ root string }

func (w testWorkspace) Path(parts ...string) string {
	return filepath.Join(append([]string{w.root}, parts...)...)
}

func newTestAppContext(t *testing.T) app.Context {
	t.Helper()
	return app.Context{
		Ctx:       context.Background(),
		Workspace: testWorkspace{root: t.TempDir()},
		Now:       time.Now(),
	}
}

// Regression test for a bug where workflow.RegisterModule was never called
// anywhere in the codebase: moduleRunners stayed empty forever, and every
// single workflow step — including all three PredefinedWorkflows — failed
// with "unknown module: <name>". This proves a module registered through
// the public API is actually reachable by Execute/executeStep/runModule.
func TestExecute_RunsRegisteredModule(t *testing.T) {
	const moduleName = "test-module-registered"
	RegisterModule(moduleName, func(_ context.Context, _ app.Context, _ map[string]interface{}) (interface{}, error) {
		return []string{"finding-a", "finding-b", "finding-c"}, nil
	})

	wf := &Workflow{
		Name:  "registration test",
		Steps: []Step{{ID: "s1", Name: "Step 1", Module: moduleName}},
	}

	report, err := Execute(newTestAppContext(t), wf, nil)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	result, ok := report.StepResults["s1"]
	if !ok {
		t.Fatalf("no result recorded for step s1")
	}
	if result.Status != "completed" {
		t.Errorf("status = %q, want %q (error: %s)", result.Status, "completed", result.Error)
	}
	// Regression guard for the *other* half of the same bug: countFindings
	// used to only recognize []interface{}/map[string]interface{}/int, so a
	// concrete []string (what every real module actually returns, just as
	// a different element type) silently counted as 0 findings forever.
	if result.FoundCount != 3 {
		t.Errorf("FoundCount = %d, want 3", result.FoundCount)
	}
}

// A module name nobody registered must still fail clearly — Execute must
// not silently treat a typo'd/unregistered module as "nothing to do".
func TestExecute_UnknownModuleFails(t *testing.T) {
	wf := &Workflow{
		Name:  "unknown module test",
		Steps: []Step{{ID: "s1", Name: "Step 1", Module: "this-module-does-not-exist"}},
	}

	_, err := Execute(newTestAppContext(t), wf, nil)
	if err == nil {
		t.Fatal("expected an error for an unregistered module, got nil")
	}
}

// Most workflow steps (see PredefinedWorkflows and the README's own example)
// never put "target" in their own Config — they rely on the workflow-level
// target (from `workflow run --target` / overrides) reaching every step
// automatically. If that injection broke, every module would run against an
// empty target.
func TestExecute_InjectsTargetIntoStepConfig(t *testing.T) {
	const moduleName = "test-module-target-injection"
	var seenTarget string
	RegisterModule(moduleName, func(_ context.Context, _ app.Context, cfg map[string]interface{}) (interface{}, error) {
		seenTarget, _ = cfg["target"].(string)
		return nil, nil
	})

	wf := &Workflow{
		Name:  "target injection test",
		Steps: []Step{{ID: "s1", Name: "Step 1", Module: moduleName}},
	}

	_, err := Execute(newTestAppContext(t), wf, map[string]interface{}{"target": "example.com"})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if seenTarget != "example.com" {
		t.Errorf("step saw target %q, want %q", seenTarget, "example.com")
	}
}

// An explicit per-step target must win over the workflow-level one.
func TestExecute_StepTargetOverridesWorkflowTarget(t *testing.T) {
	const moduleName = "test-module-target-override"
	var seenTarget string
	RegisterModule(moduleName, func(_ context.Context, _ app.Context, cfg map[string]interface{}) (interface{}, error) {
		seenTarget, _ = cfg["target"].(string)
		return nil, nil
	})

	wf := &Workflow{
		Name: "target override test",
		Steps: []Step{{
			ID: "s1", Name: "Step 1", Module: moduleName,
			Config: map[string]interface{}{"target": "specific-host.example"},
		}},
	}

	_, err := Execute(newTestAppContext(t), wf, map[string]interface{}{"target": "workflow-wide.example"})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if seenTarget != "specific-host.example" {
		t.Errorf("step saw target %q, want the step-level override %q", seenTarget, "specific-host.example")
	}
}

func TestCountFindings(t *testing.T) {
	type named struct{ X int }

	cases := []struct {
		name string
		in   interface{}
		want int
	}{
		{"nil", nil, 0},
		{"empty slice of interfaces", []interface{}{}, 0},
		{"slice of interfaces", []interface{}{1, 2}, 2},
		{"typed string slice", []string{"a", "b", "c"}, 3},
		{"typed struct slice", []named{{1}, {2}}, 2},
		{"map with count", map[string]interface{}{"count": 5}, 5},
		{"map without count", map[string]interface{}{"x": 1}, 1},
		{"bare int", 7, 7},
		{"non-nil pointer", &named{X: 1}, 1},
		{"nil pointer", (*named)(nil), 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := countFindings(tc.in); got != tc.want {
				t.Errorf("countFindings(%#v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestEvaluateCondition(t *testing.T) {
	execCtx := &ExecutionContext{
		StepResults: map[string]*StepResult{
			"recon": {FoundCount: 3, Status: "completed"},
		},
	}

	cases := []struct {
		condition string
		want      bool
	}{
		{"recon.found_count > 0", true},
		{"recon.found_count > 10", false},
		{"recon.found_count == 3", true},
		{"recon.status == completed", true},
		{"recon.status != completed", false},
		{"missing_step.found_count > 0", false},
	}

	for _, tc := range cases {
		t.Run(tc.condition, func(t *testing.T) {
			if got := evaluateCondition(execCtx, tc.condition); got != tc.want {
				t.Errorf("evaluateCondition(%q) = %v, want %v", tc.condition, got, tc.want)
			}
		})
	}
}

func TestPredefinedWorkflowsServiceStepsHavePorts(t *testing.T) {
	// Regression guard: quick-recon and full-assessment's "services" step
	// used to have no "ports" key at all (not even via a ${var} reference),
	// so services.Run always failed with "no ports specified" the moment the
	// workflow engine itself became functional.
	for name, wf := range PredefinedWorkflows {
		for _, step := range wf.Steps {
			if step.Module != "services" {
				continue
			}
			if _, ok := step.Config["ports"]; !ok {
				t.Errorf("workflow %q: step %q (module services) has no \"ports\" in its config", name, step.ID)
			}
		}
	}
}
