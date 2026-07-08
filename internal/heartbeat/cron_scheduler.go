//go:build !windows

package heartbeat

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// cronScheduler manages a crontab entry that runs the heartbeat periodically.
// The entry is tagged with a "# pmg-heartbeat" marker so Install/Remove can
// find and replace exactly PMG's line without touching the user's other jobs.
type cronScheduler struct{}

const cronMarker = "# " + taskName

func (c *cronScheduler) Install(pmgPath string) error {
	existing, err := readCrontab()
	if err != nil {
		return err
	}
	lines := stripPMGLines(existing)

	entry := fmt.Sprintf("*/%d * * * * %q cloud heartbeat >/dev/null 2>&1 %s",
		intervalMinutes, pmgPath, cronMarker)
	lines = append(lines, entry)

	return writeCrontab(strings.Join(lines, "\n") + "\n")
}

func (c *cronScheduler) Remove() error {
	existing, err := readCrontab()
	if err != nil {
		return err
	}
	lines := stripPMGLines(existing)
	out := strings.Join(lines, "\n")
	if out != "" {
		out += "\n"
	}
	return writeCrontab(out)
}

func readCrontab() (string, error) {
	cmd := exec.Command("crontab", "-l")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if strings.Contains(stderr.String(), "no crontab") {
			return "", nil
		}
		if stdout.Len() == 0 {
			return "", nil
		}
		return "", fmt.Errorf("read crontab: %w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

func writeCrontab(content string) error {
	if strings.TrimSpace(content) == "" {
		cmd := exec.Command("crontab", "-r")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil && !strings.Contains(stderr.String(), "no crontab") {
			return fmt.Errorf("clear crontab: %w: %s", err, stderr.String())
		}
		return nil
	}
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(content)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("write crontab: %w: %s", err, stderr.String())
	}
	return nil
}

func stripPMGLines(crontab string) []string {
	var out []string
	for _, line := range strings.Split(crontab, "\n") {
		if strings.Contains(line, cronMarker) {
			continue
		}
		out = append(out, line)
	}
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	return out
}
