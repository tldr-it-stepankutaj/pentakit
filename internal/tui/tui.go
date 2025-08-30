package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/tldr-it-stepankutaj/pentakit/internal/app"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/recon"
)

// model is a minimal Bubble Tea model. No icons, plain text only.
type model struct {
	appCtx app.Context
	view   string
	target string
	msg    string
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		case "r":
			// Run recon with default ports when 'r' is pressed.
			cfg := recon.RunConfig{
				Target:  m.target,
				Ports:   []int{80, 443, 8080, 22},
				Timeout: m.appCtx.Config.Timeout,
			}
			if m.target == "" {
				m.msg = "Set target first using the command line flag in CLI mode. TUI uses the compiled default for now."
				return m, nil
			}
			if err := recon.Run(m.appCtx, cfg); err != nil {
				m.msg = "Recon failed: " + err.Error()
			} else {
				m.msg = "Recon finished."
			}
			return m, nil
		}
	}
	return m, nil
}

func (m model) View() string {
	header := "Pentakit TUI (press 'r' to run recon, 'q' to quit)\n"
	body := fmt.Sprintf("Target: %s\n", m.target)
	footer := fmt.Sprintf("\nStatus: %s\n", m.msg)
	return header + body + footer
}

// Run starts the TUI. For MVP, target is empty; pass via CLI for non-TUI runs.
func Run(appCtx app.Context) error {
	initial := model{
		appCtx: appCtx,
		view:   "home",
		target: "", // For simplicity; can be persisted to workspace config later.
		msg:    "Ready.",
	}
	_, err := tea.NewProgram(initial).Run()
	return err
}
