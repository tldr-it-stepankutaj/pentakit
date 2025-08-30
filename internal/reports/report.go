package reports

import (
	"os"
	"path/filepath"
	"text/template"
)

// ReportData is the data model passed to the markdown template.
type ReportData struct {
	Date      string
	Workspace string
	Findings  []struct {
		Target   string
		Port     int
		Evidence string
	}
}

// RenderMarkdownReport renders templates/report.md.tmpl with data into outPath.
func RenderMarkdownReport(outPath string, data ReportData) error {
	// Discover template path relative to project root during runtime.
	// For simplicity, assume templates/ is alongside the binary's working dir or use an embedded FS later.
	tmplPath := filepath.Join("templates", "report.md.tmpl")

	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			return
		}
	}(f)

	return tmpl.Execute(f, data)
}
