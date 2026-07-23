//go:build windows

package heartbeat

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

// schtasksScheduler manages a Windows Task Scheduler task that runs the
// heartbeat periodically via schtasks.exe.
type schtasksScheduler struct{}

func newScheduler() Scheduler { return &schtasksScheduler{} }

// schtaskName is the registered Task Scheduler task name.
const schtaskName = "PMG Heartbeat"

// taskXMLTemplate is a Task Scheduler XML definition that runs pmg directly
// without any wrapper binary (no conhost, no VBScript).
//
// LogonType=S4U ("Service For User") runs the task with the user's token but
// without loading the user's interactive desktop. Because there is no desktop
// for conhost to render into, the console window is never shown — this is what
// eliminates the CMD flash every 15 minutes. File I/O under %USERPROFILE% and
// outbound network still work because those resolve from the token's SID, not
// from the desktop session.
//
// Key settings:
//   - LogonType: S4U        — no desktop → no console window on screen
//   - Hidden: true          — also hides the task engine UI, defense-in-depth
//   - RunLevel: HighestAvailable — elevates if the installing user is admin
//   - ExecutionTimeLimit: PT2M — kill if heartbeat hangs for 2 minutes
//   - DisallowStartIfOnBatteries/StopIfGoingOnBatteries: false — run on laptops
//
// StartBoundary is set to install time (not a fixed epoch). A StartBoundary far
// in the past leaves the task "Ready" with a computed Next Run Time that never
// actually fires (Last Result stays 0x41303 SCHED_S_TASK_HAS_NOT_RUN), so the
// repetition never begins. Anchoring the trigger to the current time makes the
// scheduler arm the repetition normally.
var taskXMLTemplate = template.Must(template.New("task").Parse(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>PMG agent heartbeat — keeps the security dashboard up to date</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT{{.IntervalMinutes}}M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>{{.StartBoundary}}</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>S4U</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Hidden>true</Hidden>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT2M</ExecutionTimeLimit>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{{.PMGPath}}</Command>
      <Arguments>cloud heartbeat</Arguments>
    </Exec>
  </Actions>
</Task>`))

func (s *schtasksScheduler) Install(pmgPath string) error {
	// Write the XML to a temp file — schtasks /XML requires a file path.
	tmp, err := os.CreateTemp("", "pmg-task-*.xml")
	if err != nil {
		return fmt.Errorf("create task xml: %w", err)
	}
	defer os.Remove(tmp.Name())

	if err := taskXMLTemplate.Execute(tmp, struct {
		PMGPath         string
		IntervalMinutes int
		StartBoundary   string
	}{
		PMGPath:         filepath.Clean(pmgPath),
		IntervalMinutes: intervalMinutes,
		StartBoundary:   time.Now().Format("2006-01-02T15:04:05"),
	}); err != nil {
		tmp.Close()
		return fmt.Errorf("render task xml: %w", err)
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
