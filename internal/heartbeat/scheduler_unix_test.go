//go:build !windows

package heartbeat

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStripPMGLines_RemovesMarkedLineOnly(t *testing.T) {
	crontab := "0 2 * * * /usr/bin/backup\n" +
		"*/15 * * * * \"/usr/local/bin/pmg\" cloud heartbeat >/dev/null 2>&1 # pmg-heartbeat\n" +
		"30 4 * * * /usr/bin/cleanup\n"

	got := stripPMGLines(crontab)

	assert.Equal(t, []string{
		"0 2 * * * /usr/bin/backup",
		"30 4 * * * /usr/bin/cleanup",
	}, got)
}

func TestStripPMGLines_EmptyCrontab(t *testing.T) {
	assert.Empty(t, stripPMGLines(""))
}

func TestStripPMGLines_OnlyPMGLine(t *testing.T) {
	crontab := "*/15 * * * * \"/usr/local/bin/pmg\" cloud heartbeat >/dev/null 2>&1 # pmg-heartbeat\n"
	assert.Empty(t, stripPMGLines(crontab))
}

func TestStripPMGLines_TrimsTrailingBlanks(t *testing.T) {
	crontab := "0 2 * * * /usr/bin/backup\n\n\n"
	got := stripPMGLines(crontab)
	assert.Equal(t, []string{"0 2 * * * /usr/bin/backup"}, got)
}

func TestStripPMGLines_IdempotentReinstall(t *testing.T) {
	// Simulate a crontab that already has a stale PMG line; stripping then
	// re-adding must not duplicate it.
	crontab := "*/15 * * * * \"/old/pmg\" cloud heartbeat >/dev/null 2>&1 # pmg-heartbeat\n" +
		"0 2 * * * /usr/bin/backup\n"
	got := stripPMGLines(crontab)
	assert.Equal(t, []string{"0 2 * * * /usr/bin/backup"}, got)
}
