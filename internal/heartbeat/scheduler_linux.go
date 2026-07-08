//go:build linux

package heartbeat

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
)

// linuxScheduler uses a systemd user timer when systemd is available (detected
// by whether systemctl --user is functional), and falls back to the cron
// scheduler otherwise. Most modern Linux distros (Ubuntu 18+, Debian 10+,
// Fedora, RHEL 8+) ship systemd; the fallback covers minimal/container installs.
type linuxScheduler struct {
	delegate Scheduler
}

func newScheduler() Scheduler {
	if systemdUserAvailable() {
		return &linuxScheduler{delegate: &systemdScheduler{}}
	}
	return &linuxScheduler{delegate: &cronScheduler{}}
}

func (s *linuxScheduler) Install(pmgPath string) error { return s.delegate.Install(pmgPath) }
func (s *linuxScheduler) Remove() error                { return s.delegate.Remove() }

// systemdAvailable returns true when `systemctl --user is-system-running` exits
// without "Failed to connect" — i.e. the user's systemd session is alive.
func systemdUserAvailable() bool {
	cmd := exec.Command("systemctl", "--user", "is-system-running")
	out, err := cmd.Output()
	if err != nil {
		// is-system-running exits non-zero for "degraded" but still prints output —
		// that still means systemd is running. Only treat it as absent when the
		// output contains the connection-failure string.
		if strings.Contains(string(out), "Failed to connect") {
			return false
		}
		// Any other non-zero (degraded, starting) still means systemd is present.
		if len(out) > 0 {
			return true
		}
		return false
	}
	return true
}

// systemdScheduler installs a systemd user service + timer pair.
type systemdScheduler struct{}

const (
	systemdServiceName = "pmg-heartbeat.service"
	systemdTimerName   = "pmg-heartbeat.timer"
)

var serviceTemplate = template.Must(template.New("svc").Parse(`[Unit]
Description=PMG agent heartbeat

[Service]
Type=oneshot
ExecStart={{.PMGPath}} cloud heartbeat
`))

var timerTemplate = template.Must(template.New("tmr").Parse(`[Unit]
Description=PMG agent heartbeat timer

[Timer]
OnBootSec=2min
OnUnitActiveSec={{.IntervalMinutes}}min
Persistent=true

[Install]
WantedBy=timers.target
`))

func (s *systemdScheduler) Install(pmgPath string) error {
	dir, err := systemdUserDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create systemd user dir: %w", err)
	}

	data := struct {
		PMGPath         string
		IntervalMinutes int
	}{filepath.Clean(pmgPath), intervalMinutes}

	if err := writeTemplate(filepath.Join(dir, systemdServiceName), serviceTemplate, data); err != nil {
		return err
	}
	if err := writeTemplate(filepath.Join(dir, systemdTimerName), timerTemplate, data); err != nil {
		return err
	}

	// Reload unit files, enable the timer so it survives logout, start it now.
	for _, args := range [][]string{
		{"--user", "daemon-reload"},
		{"--user", "enable", "--now", systemdTimerName},
	} {
		if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, out)
		}
	}
	return nil
}

func (s *systemdScheduler) Remove() error {
	// Stop and disable — ignore errors if the timer never existed.
	exec.Command("systemctl", "--user", "disable", "--now", systemdTimerName).Run() //nolint:errcheck

	dir, err := systemdUserDir()
	if err != nil {
		return err
	}
	for _, name := range []string{systemdServiceName, systemdTimerName} {
		path := filepath.Join(dir, name)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", name, err)
		}
	}
	exec.Command("systemctl", "--user", "daemon-reload").Run() //nolint:errcheck
	return nil
}

func systemdUserDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, ".config", "systemd", "user"), nil
}

func writeTemplate(path string, tmpl *template.Template, data any) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", filepath.Base(path), err)
	}
	defer f.Close()
	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}
