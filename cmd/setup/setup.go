package setup

import (
	"fmt"
	"os"
	"runtime"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/alias"
	"github.com/safedep/pmg/internal/heartbeat"
	"github.com/safedep/pmg/internal/shim"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/internal/version"
	"github.com/spf13/cobra"
)

var setupRemoveConfigFile = false

func NewSetupCommand() *cobra.Command {
	setupCmd := &cobra.Command{
		Use:   "setup",
		Short: "Manage PMG shell integration (aliases and shims)",
		Long:  "Setup and manage PMG config, shell aliases and PATH shims that allow you to use package manager commands with security guardrails.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	setupCmd.AddCommand(NewInstallCommand())
	setupCmd.AddCommand(NewRemoveCommand())
	setupCmd.AddCommand(NewInfoCommand())

	return setupCmd
}

func NewInstallCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "install",
		Short:        "Setup PMG config, aliases, and shims for package managers (npm, pnpm, pip, and more)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(ui.GeneratePMGBanner(version.Version, version.Commit))
			return install()
		},
	}
}

func install() error {
	if err := config.WriteTemplateConfig(); err != nil {
		return fmt.Errorf("failed to write template config: %w", err)
	}

	if config.Get().IsManaged() {
		fmt.Printf("%s %s\n", ui.Colors.Dim("ℹ"),
			fmt.Sprintf("Using globally managed config: %s", config.Get().ConfigFilePath()))
	}

	shimMgr, err := shim.NewDefaultShimManager()
	if err != nil {
		return fmt.Errorf("failed to create shim manager: %w", err)
	}

	if err := shimMgr.Install(); err != nil {
		return fmt.Errorf("failed to install shims: %w", err)
	}

	installHeartbeatSchedule()

	if runtime.GOOS == "windows" {
		fmt.Printf("%s %s\n", ui.Colors.Green("✓"), "PMG config written successfully")
		fmt.Printf("   %s\n", ui.Colors.Dim(fmt.Sprintf("Config:  %s", config.Get().ConfigDir())))
		fmt.Printf("%s %s\n", ui.Colors.Green("✓"), "PATH shims installed — npm, pip and other package managers will be intercepted automatically")
		fmt.Printf("   %s\n", ui.Colors.Dim(fmt.Sprintf("Shims:   %s", shimMgr.GetBinDir())))
		fmt.Printf("\n%s Restart your terminal for PATH changes to take effect.\n", ui.Colors.Yellow("⚠"))
		return nil
	}

	cfg := alias.DefaultConfig()
	rcFileManager, err := alias.NewDefaultRcFileManager(cfg.RcFileName)
	if err != nil {
		return fmt.Errorf("failed to create alias manager: %w", err)
	}

	aliasManager := alias.New(cfg, rcFileManager)
	if err := aliasManager.Install(); err != nil {
		return fmt.Errorf("failed to install aliases: %w", err)
	}

	ui.PrintSetupInstallCmdInfo(aliasManager.GetRcPath(), shimMgr.GetBinDir(), config.Get().ConfigDir())
	return nil
}

// installHeartbeatSchedule registers a periodic `pmg cloud heartbeat` task so the
// dashboard sees the machine as online while it is powered on, even when no
// package manager command runs. Only meaningful when enrolled with a cloud
// server; failures are non-fatal (best-effort, logged) so they never block setup.
func installHeartbeatSchedule() {
	cfg := config.Get()
	if !cfg.Config.Cloud.Enabled || cfg.Config.Cloud.APIKey == "" {
		return
	}
	pmgPath, err := os.Executable()
	if err != nil {
		log.Warnf("heartbeat schedule: failed to resolve pmg path: %v", err)
		return
	}
	if err := heartbeat.NewScheduler().Install(pmgPath); err != nil {
		log.Warnf("heartbeat schedule: failed to install periodic heartbeat: %v", err)
		return
	}
	fmt.Printf("%s %s\n", ui.Colors.Green("✓"),
		"Periodic heartbeat scheduled — dashboard will show this machine as online while it is on")
}

// removeHeartbeatSchedule removes the periodic heartbeat task. Best-effort; logged on failure.
func removeHeartbeatSchedule() {
	if err := heartbeat.NewScheduler().Remove(); err != nil {
		log.Warnf("heartbeat schedule: failed to remove periodic heartbeat: %v", err)
	}
}

func NewRemoveCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "remove",
		Short:        "Removes pmg aliases and shims from the user's shell config.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(ui.GeneratePMGBanner(version.Version, version.Commit))

			if setupRemoveConfigFile {
				// Only ever remove the per-user file; the globally managed
				// config is not ours to delete from a per-user uninstall.
				if err := config.RemoveUserConfigFile(); err != nil {
					return err
				}
			}

			removeHeartbeatSchedule()

			if runtime.GOOS == "windows" {
				shimMgr, err := shim.NewDefaultShimManager()
				if err != nil {
					return fmt.Errorf("failed to create shim manager: %w", err)
				}
				if err := shimMgr.Remove(); err != nil {
					return fmt.Errorf("failed to remove shims: %w", err)
				}
				fmt.Printf("%s %s\n", ui.Colors.Green("✓"), "PMG shims removed. Restart your terminal for changes to take effect.")
				return nil
			}

			cfg := alias.DefaultConfig()
			rcFileManager, err := alias.NewDefaultRcFileManager(cfg.RcFileName)
			if err != nil {
				return err
			}

			aliasManager := alias.New(cfg, rcFileManager)
			if err := aliasManager.Remove(); err != nil {
				return fmt.Errorf("failed to remove aliases: %w", err)
			}

			shimMgr, err := shim.NewDefaultShimManager()
			if err != nil {
				return fmt.Errorf("failed to create shim manager: %w", err)
			}

			if err := shimMgr.Remove(); err != nil {
				return fmt.Errorf("failed to remove shims: %w", err)
			}

			fmt.Printf("%s %s\n", ui.Colors.Green("✓"), "PMG aliases and shims removed. Restart your terminal for changes to take effect")
			return nil
		},
	}

	cmd.Flags().BoolVar(&setupRemoveConfigFile, "config-file", false, "Remove the config file")
	return cmd
}
