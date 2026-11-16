package pentakit

import (
	"reflect"
	"testing"
	"time"
)

func TestParsePortSpec(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"", nil},
		{"22", []int{22}},
		{"22,80,443", []int{22, 80, 443}},
		{"1-5", []int{1, 2, 3, 4, 5}},
		{"22,80,1000-1003", []int{22, 80, 1000, 1001, 1002, 1003}},
		{" 22 , 80 ", []int{22, 80}},
		{"5-1", nil},              // reversed range is invalid, not silently reversed
		{"abc", nil},              // garbage is dropped, not a panic
		{"22,,80", []int{22, 80}}, // empty segment from a stray comma is skipped
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := parsePortSpec(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parsePortSpec(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestCfgPorts(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]interface{}
		want []int
	}{
		{"missing key", map[string]interface{}{}, nil},
		{"native []int (Go literal, e.g. PredefinedWorkflows)", map[string]interface{}{
			"ports": []int{80, 443},
		}, []int{80, 443}},
		{"[]interface{} of float64 (JSON-decoded)", map[string]interface{}{
			"ports": []interface{}{80.0, 443.0},
		}, []int{80, 443}},
		{"[]interface{} of int (YAML-decoded)", map[string]interface{}{
			"ports": []interface{}{80, 443},
		}, []int{80, 443}},
		{"range string (e.g. full-assessment)", map[string]interface{}{
			"ports": "1-3",
		}, []int{1, 2, 3}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cfgPorts(tc.cfg, "ports")
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("cfgPorts(%v) = %v, want %v", tc.cfg, got, tc.want)
			}
		})
	}
}

func TestCfgStringSlice(t *testing.T) {
	cfg := map[string]interface{}{
		"template_tags": []interface{}{"cve", "rce"},
		"tags":          []string{"should-not-be-used"},
	}
	// primary key present: altKey must be ignored, not merged.
	got := cfgStringSlice(cfg, "template_tags", "tags")
	want := []string{"cve", "rce"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("cfgStringSlice = %v, want %v", got, want)
	}

	// primary key absent: falls back to altKey.
	got = cfgStringSlice(map[string]interface{}{"tags": []string{"a", "b"}}, "template_tags", "tags")
	want = []string{"a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("cfgStringSlice fallback = %v, want %v", got, want)
	}

	if got := cfgStringSlice(map[string]interface{}{}, "missing", ""); got != nil {
		t.Errorf("cfgStringSlice on empty cfg = %v, want nil", got)
	}
}

func TestCfgBoolIntStringDuration(t *testing.T) {
	cfg := map[string]interface{}{
		"flag_true":  true,
		"int_native": 5,
		"int_float":  float64(7), // JSON-decoded numbers land as float64
		"int_string": "9",
		"name":       "example.com",
		"empty_name": "",
		"dur":        "15s",
	}

	if got := cfgBool(cfg, "flag_true", false); got != true {
		t.Errorf("cfgBool = %v, want true", got)
	}
	if got := cfgBool(cfg, "missing_flag", true); got != true {
		t.Errorf("cfgBool default = %v, want true", got)
	}

	if got := cfgInt(cfg, "int_native", 0); got != 5 {
		t.Errorf("cfgInt (int) = %d, want 5", got)
	}
	if got := cfgInt(cfg, "int_float", 0); got != 7 {
		t.Errorf("cfgInt (float64) = %d, want 7", got)
	}
	if got := cfgInt(cfg, "int_string", 0); got != 9 {
		t.Errorf("cfgInt (string) = %d, want 9", got)
	}
	if got := cfgInt(cfg, "missing_int", 42); got != 42 {
		t.Errorf("cfgInt default = %d, want 42", got)
	}

	if got := cfgString(cfg, "name", "fallback"); got != "example.com" {
		t.Errorf("cfgString = %q, want %q", got, "example.com")
	}
	// An explicitly empty string must not win over the fallback — workflow
	// steps routinely leave "target" unset, and an empty override should not
	// shadow the workflow-level target auto-injected by executeStep.
	if got := cfgString(cfg, "empty_name", "fallback"); got != "fallback" {
		t.Errorf("cfgString with empty value = %q, want fallback %q", got, "fallback")
	}

	if got := cfgDuration(cfg, "dur", time.Second); got != 15*time.Second {
		t.Errorf("cfgDuration = %v, want 15s", got)
	}
	if got := cfgDuration(cfg, "missing_dur", 3*time.Second); got != 3*time.Second {
		t.Errorf("cfgDuration default = %v, want 3s", got)
	}
}
