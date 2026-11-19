package heartbeat

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"text/template"
)

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
//   - no RunLevel           — least privilege; a heartbeat is one HTTP POST and
//     does not need elevation, which also avoids a "runs elevated" signal
//   - ExecutionTimeLimit: PT2M — kill if heartbeat hangs for 2 minutes
//   - DisallowStartIfOnBatteries/StopIfGoingOnBatteries: false — run on laptops
//
// StartBoundary is set to install time (not a fixed epoch). A StartBoundary far
// in the past leaves the task "Ready" with a computed Next Run Time that never
// actually fires (Last Result stays 0x41303 SCHED_S_TASK_HAS_NOT_RUN), so the
// repetition never begins. Anchoring the trigger to the current time makes the
// scheduler arm the repetition normally.
var taskXMLTemplate = template.Must(template.New("task").Funcs(template.FuncMap{
	"xml": escapeXML,
}).Parse(`<?xml version="1.0" encoding="UTF-16"?>
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
      <Command>{{xml .PMGPath}}</Command>
      <Arguments>cloud heartbeat</Arguments>
    </Exec>
  </Actions>
</Task>`))

func escapeXML(s string) (string, error) {
	var b bytes.Buffer
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return "", err
	}
	return b.String(), nil
}

func renderTaskXML(pmgPath string, intervalMinutes int, startBoundary string) (string, error) {
	var out bytes.Buffer
	err := taskXMLTemplate.Execute(&out, struct {
		PMGPath         string
		IntervalMinutes int
		StartBoundary   string
	}{pmgPath, intervalMinutes, startBoundary})
	if err != nil {
		return "", fmt.Errorf("render task xml: %w", err)
	}
	return out.String(), nil
}
