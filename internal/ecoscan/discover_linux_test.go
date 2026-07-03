//go:build linux

package ecoscan

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProcMountsSkipsVirtualAndNetworkFilesystems(t *testing.T) {
	data := `sysfs /sys sysfs rw 0 0
proc /proc proc rw 0 0
/dev/sda1 / ext4 rw,relatime 0 0
/dev/sda2 /home ext4 rw,relatime 0 0
tmpfs /run tmpfs rw 0 0
fileserver:/export /mnt/data nfs4 rw 0 0
//user@server/share /mnt/smb cifs rw 0 0
`
	roots := parseProcMounts(data)
	assert.ElementsMatch(t, []string{"/", "/home"}, roots)
}

func TestParseProcMountsDedupesMountPoints(t *testing.T) {
	data := "/dev/sda1 / ext4 rw 0 0\n/dev/sda1 / ext4 rw 0 0\n"
	assert.Equal(t, []string{"/"}, parseProcMounts(data))
}

func TestRootsFallsBackToSlashOnMissingProcMounts(t *testing.T) {
	roots, err := Roots()
	require.NoError(t, err)
	require.NotEmpty(t, roots)
}
