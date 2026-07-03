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
	"proc":     true,
	"sysfs":    true,
	"devtmpfs": true,
	"tmpfs":    true,
	"cgroup":   true,
	"cgroup2":  true,
	"nfs":      true,
	"nfs4":     true,
	"cifs":     true,
	"smbfs":    true,
	"autofs":   true,
}

// Roots returns every locally-mounted filesystem's mount point, skipping
// virtual and network filesystems, by parsing /proc/mounts. Falls back to a
// plain "/" root if /proc/mounts can't be read.
func Roots() ([]string, error) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return []string{"/"}, nil
	}
	roots := parseProcMounts(string(data))
	if len(roots) == 0 {
		return []string{"/"}, nil
	}
	return roots, nil
}

// parseProcMounts extracts local (non-virtual, non-network) mount points
// from /proc/mounts-formatted content. Each line is:
// "device mountpoint fstype options freq passno".
func parseProcMounts(data string) []string {
	var roots []string
	seen := map[string]bool{}

	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		mountPoint, fsType := fields[1], fields[2]
		if linuxSkipFSTypes[fsType] || seen[mountPoint] {
			continue
		}
		seen[mountPoint] = true
		roots = append(roots, mountPoint)
	}
	return roots
}
