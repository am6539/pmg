//go:build windows

package heartbeat

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// schtasksScheduler manages a Windows Task Scheduler task that runs the
// heartbeat periodically via schtasks.exe.
type schtasksScheduler struct{}

func newScheduler() Scheduler { return &schtasksScheduler{} }

// schtaskName is the registered Task Scheduler task name.
const schtaskName = "PMG Heartbeat"

func (s *schtasksScheduler) Install(pmgPath string) error {
	// Write the XML to a temp file — schtasks /XML requires a file path.
	tmp, err := os.CreateTemp("", "pmg-task-*.xml")
	if err != nil {
		return fmt.Errorf("create task xml: %w", err)
	}
	defer os.Remove(tmp.Name())

	xmlBody, err := renderTaskXML(filepath.Clean(pmgPath), intervalMinutes, time.Now().Format("2006-01-02T15:04:05"))
	if err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(xmlBody); err != nil {
		tmp.Close()
		return fmt.Errorf("write task xml: %w", err)
	}
	tmp.Close()

	cmd := exec.Command("schtasks",
		"/Create",
		"/TN", schtaskName,
		"/XML", tmp.Name(),
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
		if strings.Contains(stderr.String(), "cannot find") ||
			strings.Contains(stderr.String(), "does not exist") {
			return nil
		}
		return fmt.Errorf("delete scheduled task: %w: %s", err, stderr.String())
	}
	return nil
}
