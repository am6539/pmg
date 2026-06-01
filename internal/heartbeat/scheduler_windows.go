//go:build windows

package heartbeat

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// schtasksScheduler manages a Windows Task Scheduler task that runs the
// heartbeat periodically via schtasks.exe.
type schtasksScheduler struct{}

func newScheduler() Scheduler { return &schtasksScheduler{} }

// schtaskName is the registered Task Scheduler task name.
const schtaskName = "PMG Heartbeat"

// launcherName is the VBScript shim that runs pmg with no visible console.
const launcherName = "pmg-heartbeat.vbs"

// launcherPath returns where the VBScript launcher lives (next to the binary).
func launcherPath(pmgPath string) string {
	return filepath.Join(filepath.Dir(pmgPath), launcherName)
}

func (s *schtasksScheduler) Install(pmgPath string) error {
	// pmg.exe is a console app; when Task Scheduler launches it directly a CMD
	// window flashes on screen every interval. We run it through a VBScript
	// shim with WScript.Shell.Run(window=0) so it executes fully hidden.
	vbsPath := launcherPath(pmgPath)
	// In a VBS string literal each " is doubled. We want Run to receive the
	// command:  "C:\...\pmg.exe" cloud heartbeat
	runArg := `"""` + pmgPath + `"" cloud heartbeat"`
	vbs := `CreateObject("WScript.Shell").Run ` + runArg + `, 0, False` + "\r\n"
	if err := os.WriteFile(vbsPath, []byte(vbs), 0o644); err != nil {
		return fmt.Errorf("write heartbeat launcher: %w", err)
	}

	// /F overwrites an existing task so re-running setup install is idempotent.
	cmd := exec.Command("schtasks",
		"/Create",
		"/TN", schtaskName,
		"/TR", fmt.Sprintf(`wscript.exe "%s"`, vbsPath),
		"/SC", "MINUTE",
		"/MO", fmt.Sprintf("%d", intervalMinutes),
		"/F",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("create scheduled task: %w: %s", err, stderr.String())
	}
	return nil
}

func (s *schtasksScheduler) Remove() error {
	cmd := exec.Command("schtasks", "/Delete", "/TN", schtaskName, "/F")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Deleting a task that doesn't exist is not an error for us.
		if !strings.Contains(stderr.String(), "cannot find") &&
			!strings.Contains(stderr.String(), "does not exist") {
			return fmt.Errorf("delete scheduled task: %w: %s", err, stderr.String())
		}
	}
	// Best-effort cleanup of the launcher; resolve via the running binary path.
	if exe, err := os.Executable(); err == nil {
		_ = os.Remove(launcherPath(exe))
	}
	return nil
}
