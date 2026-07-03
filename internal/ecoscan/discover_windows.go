//go:build windows

package ecoscan

import (
	"os"
	"syscall"
)

// Roots returns every drive letter currently present on the system, e.g.
// []string{`C:\`, `D:\`}, by querying the Windows GetLogicalDrives bitmask.
func Roots() ([]string, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getLogicalDrives := kernel32.NewProc("GetLogicalDrives")

	ret, _, _ := getLogicalDrives.Call()
	mask := uint32(ret)

	var roots []string
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		drive := string(rune('A'+i)) + `:\`
		if _, err := os.Stat(drive); err == nil {
			roots = append(roots, drive)
		}
	}
	return roots, nil
}
