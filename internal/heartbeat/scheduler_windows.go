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
	// /F overwrites an existing task so re-running setup install is idempotent.
	// The action is quoted to tolerate spaces in the binary path.
	cmd := exec.Command("schtasks",
		"/Create",
		"/TN", schtaskName,
		"/TR", fmt.Sprintf(`"%s" cloud heartbeat`, pmgPath),
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
