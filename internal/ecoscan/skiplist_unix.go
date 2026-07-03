//go:build !windows

package ecoscan

// unixSkipPaths are exact paths pruned outright: Linux virtual/pseudo
// filesystems and macOS system-internal paths. Shared between Linux and
// macOS for simplicity — an entry that never matches on the other OS is
// harmless (mirrors the existing internal/heartbeat/scheduler_unix.go
// convention of grouping Linux+macOS under one !windows build tag).
var unixSkipPaths = map[string]bool{
	"/proc":           true,
	"/sys":            true,
	"/dev":            true,
	"/run":            true,
	"/System":         true,
	"/private/var/vm": true,
}

// ShouldSkipDir reports whether path should be pruned from the ecosystem scan walk.
func ShouldSkipDir(path string) bool {
	return unixSkipPaths[path]
}
