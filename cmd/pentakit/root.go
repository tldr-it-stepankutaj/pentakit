package pentakit

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/tldr-it-stepankutaj/pentakit/internal/app"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules"
	"github.com/tldr-it-stepankutaj/pentakit/internal/modules/recon"
	"github.com/tldr-it-stepankutaj/pentakit/internal/tui"
	"github.com/tldr-it-stepankutaj/pentakit/internal/workspace"
	"github.com/tldr-it-stepankutaj/pentakit/pkg/version"
)

var rootCmd = &cobra.Command{
	Use:   "pentakit",
	Short: "Pentakit: extensible pentest toolkit (CLI/TUI)",
	Long:  "Pentakit is an extensible Go-based toolkit for repeatable pentest workflows. Use CLI by default or TUI with --tui.",
	RunE: func(cmd *cobra.Command, args []string) error {
		// When no subcommand is provided, either start TUI (if --tui) or show help.
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
	rootCmd.AddCommand(versionCmd)
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
		cfg := app.MustLoadConfigFromViper()
		ws, err := workspace.Ensure(cfg.Workspace)
		if err != nil {
			return err
		}
		target, _ := cmd.Flags().GetString("target")
		if target == "" {
			return fmt.Errorf("target is required (use --target)")
		}
		timeout := viper.GetDuration("timeout")

		appCtx := app.Context{
			Ctx:       context.Background(),
			Config:    cfg,
			Workspace: ws,
			Now:       time.Now(),
		}

		reg := modules.NewRegistry()
		reg.Register(recon.New())

		runCfg := recon.RunConfig{
			Target:  target,
			Timeout: timeout,
			Ports:   []int{80, 443, 8080, 8443, 22, 3389, 5432, 3306},
		}
		return recon.Run(appCtx, runCfg)
	},
}

func init() {
	reconCmd.Flags().String("target", "", "Single target (IPv4/IPv6 or hostname)")
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
