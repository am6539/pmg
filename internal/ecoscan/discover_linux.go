//go:build linux

package ecoscan

import (
	"os"
	"strings"
)

// linuxSkipFSTypes are filesystem types excluded from the walk: virtual/pseudo
// filesystems (which contain no real installed packages) and network
// filesystems (which can be slow or hang under load).
var linuxSkipFSTypes = map[string]bool{
	"proc":        true,
	"sysfs":       true,
	"devtmpfs":    true,
	"tmpfs":       true,
	"cgroup":      true,
	"cgroup2":     true,
	"nfs":         true,
	"nfs4":        true,
	"cifs":        true,
	"smbfs":       true,
	"autofs":      true,
	"9p":          true, // WSL2 Windows drive passthrough mounts (/mnt/c, /mnt/d, etc.)
	"rootfs":      true, // initramfs root placeholder (/init on WSL2)
	"overlay":     true, // union mounts — WSL2 internals, Docker layers (no user-installed packages)
	"binfmt_misc": true,
	"tracefs":     true,
	"debugfs":     true,
	"configfs":    true,
	"fusectl":     true,
	"hugetlbfs":   true,
	"mqueue":      true,
	"devpts":      true,
	"pstore":      true,
	"securityfs":  true,
	"efivarfs":    true,
}

// linuxSkippedMountPoints holds mount points whose filesystem type is in
// linuxSkipFSTypes. It is populated by Roots() so that ShouldSkipDir can
// prune them during the walk even though they appear as subdirectories under
// an accepted root (e.g. /mnt/c under / on WSL2).
var linuxSkippedMountPoints = map[string]bool{}

// Roots returns every locally-mounted filesystem's mount point, skipping
// virtual and network filesystems, by parsing /proc/mounts. Falls back to a
// plain "/" root if /proc/mounts can't be read.
// As a side-effect it populates linuxSkippedMountPoints so that ShouldSkipDir
// can prune those paths during the walk.
func Roots() ([]string, error) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return []string{"/"}, nil
	}
	roots, skipped := parseProcMounts(string(data))
	linuxSkippedMountPoints = skipped
	if len(roots) == 0 {
		return []string{"/"}, nil
	}
	return roots, nil
}

// parseProcMounts extracts local (non-virtual, non-network) mount points
// from /proc/mounts-formatted content. Each line is:
// "device mountpoint fstype options freq passno".
// Bind mounts (same device as an already-accepted mount point) are skipped to
// avoid scanning the same filesystem tree twice (e.g. WSL2 bind-mounts / onto
// /mnt/wslg/distro using the same device node).
// It returns (acceptedRoots, skippedMountPoints) — the second map lets
// ShouldSkipDir prune those paths during the walk.
func parseProcMounts(data string) ([]string, map[string]bool) {
	var roots []string
	seenMountPoint := map[string]bool{}
	seenDevice := map[string]bool{}
	skipped := map[string]bool{}

	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		device, mountPoint, fsType := fields[0], fields[1], fields[2]
		if linuxSkipFSTypes[fsType] || seenMountPoint[mountPoint] || seenDevice[device] {
			if mountPoint != "/" {
				skipped[mountPoint] = true
			}
			continue
		}
		seenMountPoint[mountPoint] = true
		seenDevice[device] = true
		roots = append(roots, mountPoint)
	}
	return roots, skipped
}

