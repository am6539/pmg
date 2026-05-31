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

func newScheduler() Scheduler { return &cronScheduler{} }

const cronMarker = "# " + taskName

func (c *cronScheduler) Install(pmgPath string) error {
	existing, err := readCrontab()
	if err != nil {
		return err
	}
	lines := stripPMGLines(existing)

	// */15 * * * * "pmg" cloud heartbeat >/dev/null 2>&1 # pmg-heartbeat
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

// readCrontab returns the current crontab contents, or "" when none is set.
func readCrontab() (string, error) {
	cmd := exec.Command("crontab", "-l")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// `crontab -l` exits non-zero when no crontab exists; treat as empty.
		if strings.Contains(stderr.String(), "no crontab") {
			return "", nil
		}
		// Some cron implementations just print nothing with a non-zero code.
		if stdout.Len() == 0 {
			return "", nil
		}
		return "", fmt.Errorf("read crontab: %w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

// writeCrontab replaces the crontab with content (empty content clears it).
func writeCrontab(content string) error {
	if strings.TrimSpace(content) == "" {
		// `crontab -r` removes the crontab; ignore "no crontab" errors.
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

// stripPMGLines drops any line carrying the PMG heartbeat marker and trailing blanks.
func stripPMGLines(crontab string) []string {
	var out []string
	for _, line := range strings.Split(crontab, "\n") {
		if strings.Contains(line, cronMarker) {
			continue
		}
		out = append(out, line)
	}
	// Trim trailing empty lines for a clean rewrite.
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	return out
}
