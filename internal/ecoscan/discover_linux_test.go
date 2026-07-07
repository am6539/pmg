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
	roots, _ := parseProcMounts(data)
	assert.ElementsMatch(t, []string{"/", "/home"}, roots)
}

func TestParseProcMountsDedupesMountPoints(t *testing.T) {
	data := "/dev/sda1 / ext4 rw 0 0\n/dev/sda1 / ext4 rw 0 0\n"
	roots, _ := parseProcMounts(data)
	assert.Equal(t, []string{"/"}, roots)
}

func TestParseProcMountsSkipsWSL2PseudoFilesystems(t *testing.T) {
	// Mirrors a real WSL2 /proc/mounts snapshot: 9p is Windows drive passthrough,
	// overlay is WSL internal, rootfs is the initramfs placeholder,
	// and /mnt/wslg/distro is a bind re-mount of / (same device /dev/sdd).
	data := `/dev/sdc / ext4 rw 0 0
/dev/sdd /home/user ext4 rw 0 0
C:\ /mnt/c 9p rw 0 0
D:\ /mnt/d 9p rw 0 0
none /init rootfs ro 0 0
none /mnt/wslg/doc overlay ro 0 0
none /usr/lib/wsl/lib overlay ro 0 0
/dev/sdc /mnt/wslg/distro ext4 ro 0 0
`
	roots, skipped := parseProcMounts(data)
	assert.ElementsMatch(t, []string{"/", "/home/user"}, roots)
	assert.True(t, skipped["/mnt/c"])
	assert.True(t, skipped["/mnt/d"])
	assert.True(t, skipped["/init"])
	assert.True(t, skipped["/mnt/wslg/doc"])
	assert.True(t, skipped["/mnt/wslg/distro"])
}

func TestRootsFallsBackToSlashOnMissingProcMounts(t *testing.T) {
	roots, err := Roots()
	require.NoError(t, err)
	require.NotEmpty(t, roots)
}
