//go:build windows

package ecoscan

import "strings"

// windowsSkipSuffixes are case-insensitive path suffixes pruned outright:
// OS internals, the Windows Store app package cache, and drive-level
// trash/system metadata folders that appear on every Windows drive.
var windowsSkipSuffixes = []string{
	`\Windows`,
	`\Program Files\WindowsApps`,
	`\$Recycle.Bin`,
	`\System Volume Information`,
}

// ShouldSkipDir reports whether path should be pruned from the ecosystem scan walk.
func ShouldSkipDir(path string) bool {
	lower := strings.ToLower(path)
	for _, suffix := range windowsSkipSuffixes {
		if strings.HasSuffix(lower, strings.ToLower(suffix)) {
			return true
		}
	}
	return false
}
