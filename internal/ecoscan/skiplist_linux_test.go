//go:build linux

package ecoscan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShouldSkipDirLinux(t *testing.T) {
	cases := []struct {
		path string
		skip bool
	}{
		{"/proc", true},
		{"/sys", true},
		{"/dev", true},
		{"/run", true},
		{"/home/dev/code", false},
		{"/usr/local/lib/python3.11/dist-packages", false},
	}
	for _, c := range cases {
		assert.Equal(t, c.skip, ShouldSkipDir(c.path), c.path)
	}
}

func TestShouldSkipDirLinuxSkipsWSL2WindowsDrives(t *testing.T) {
	// Simulate Roots() having been called and populated linuxSkippedMountPoints
	// from /proc/mounts where /mnt/c and /mnt/d are 9p (WSL2 Windows drives).
	orig := linuxSkippedMountPoints
	defer func() { linuxSkippedMountPoints = orig }()

	linuxSkippedMountPoints = map[string]bool{
		"/mnt/c": true,
		"/mnt/d": true,
	}

	assert.True(t, ShouldSkipDir("/mnt/c"))
	assert.True(t, ShouldSkipDir("/mnt/d"))
	assert.False(t, ShouldSkipDir("/mnt/data")) // legitimate local ext4 mount
}
