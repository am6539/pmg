//go:build darwin

package ecoscan

// unixSkipPaths are exact paths pruned outright: macOS system-internal paths.
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

