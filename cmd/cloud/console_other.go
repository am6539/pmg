//go:build !windows

package cloud

// hideConsoleWindowIfOwned is a no-op on non-Windows platforms.
func hideConsoleWindowIfOwned() {}
