//go:build darwin

package ecoscan

import (
	"os"
	"os/exec"
	"strings"
)

// networkFSMarkers are filesystem type tags the `mount` command prints for
// network-backed shares.
var networkFSMarkers = []string{"smbfs", "nfs", "afpfs", "webdav"}

// Roots returns "/" plus every mounted volume under /Volumes, skipping
// network-mounted shares on a best-effort basis (avoids the walk hanging on
// a slow or disconnected network share).
func Roots() ([]string, error) {
	roots := []string{"/"}

	entries, err := os.ReadDir("/Volumes")
	if err != nil {
		return roots, nil
	}

	networkMounts := networkMountPoints()
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := "/Volumes/" + e.Name()
		if networkMounts[path] {
			continue
		}
		roots = append(roots, path)
	}
	return roots, nil
}

// networkMountPoints runs `mount` and returns the set of mount points backed
// by a network filesystem.
func networkMountPoints() map[string]bool {
	out, err := exec.Command("mount").Output()
	if err != nil {
		return map[string]bool{}
	}
	return parseNetworkMountPoints(string(out))
}

// parseNetworkMountPoints parses macOS `mount` output lines of the form:
// "//user@server/share on /Volumes/share (smbfs, nodev, nosuid)"
func parseNetworkMountPoints(output string) map[string]bool {
	result := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		idx := strings.Index(line, " on ")
		if idx == -1 {
			continue
		}
		rest := line[idx+len(" on "):]
		parenIdx := strings.Index(rest, " (")
		if parenIdx == -1 {
			continue
		}
		mountPoint := rest[:parenIdx]
		fsInfo := rest[parenIdx:]
		for _, marker := range networkFSMarkers {
			if strings.Contains(fsInfo, marker) {
				result[mountPoint] = true
				break
			}
		}
	}
	return result
}
