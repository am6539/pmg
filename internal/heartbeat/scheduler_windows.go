//go:build windows

package heartbeat

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// schtasksScheduler manages a Windows Task Scheduler task that runs the
// heartbeat periodically via schtasks.exe.
type schtasksScheduler struct{}

func newScheduler() Scheduler { return &schtasksScheduler{} }

// schtaskName is the registered Task Scheduler task name.
const schtaskName = "PMG Heartbeat"

func (s *schtasksScheduler) Install(pmgPath string) error {
	// Run the heartbeat through conhost.exe --headless. conhost is a trusted
	// Windows system binary (System32) that runs a console application inside a
	// headless pseudo-console with NO visible window — eliminating the CMD flash
	// entirely, unlike ShowWindow(SW_HIDE) which only hides the window after the
	// OS has already created and shown it. This avoids both the flash and the
	// hidden-window VBScript shim that antivirus/EDR flag as a LOLBin pattern.
	cmd := exec.Command("schtasks",
		"/Create",
		"/TN", schtaskName,
		"/TR", fmt.Sprintf(`conhost.exe --headless "%s" cloud heartbeat`, pmgPath),
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
		if strings.Contains(stderr.String(), "cannot find") ||
			strings.Contains(stderr.String(), "does not exist") {
			return nil
		}
		return fmt.Errorf("delete scheduled task: %w: %s", err, stderr.String())
	}
	return nil
}
