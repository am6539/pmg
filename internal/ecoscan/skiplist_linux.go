//go:build linux

package ecoscan

// linuxStaticSkipPaths are exact paths pruned outright during the walk:
// Linux virtual/pseudo filesystem mount points that are always present.
var linuxStaticSkipPaths = map[string]bool{
	"/proc": true,
	"/sys":  true,
	"/dev":  true,
	"/run":  true,
}

// ShouldSkipDir reports whether path should be pruned from the ecosystem scan
// walk. On Linux it checks both the static pseudo-filesystem list and any
// mount points whose filesystem type was excluded by parseProcMounts (e.g.
// WSL2 Windows drive passthrough mounts like /mnt/c).
func ShouldSkipDir(path string) bool {
	return linuxStaticSkipPaths[path] || linuxSkippedMountPoints[path]
}
