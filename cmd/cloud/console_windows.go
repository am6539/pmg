//go:build windows

package cloud

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// hideConsoleWindowIfOwned hides this process's console window, but ONLY when
// pmg is the sole process attached to that console — i.e. when launched by the
// Task Scheduler with its own fresh console. When pmg shares a console with a
// user's terminal (interactive `pmg cloud heartbeat`), it leaves it alone so
// it never hides the user's terminal.
//
// This avoids the periodic CMD-window flash from the scheduled heartbeat
// without shipping a hidden-window VBScript launcher (which AV/EDR flag).
func hideConsoleWindowIfOwned() {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	hwnd, _, _ := kernel32.NewProc("GetConsoleWindow").Call()
	if hwnd == 0 {
		return // no console attached (e.g. detached background child)
	}

	// GetConsoleProcessList returns how many processes share this console.
	// 1 means we own it alone → safe to hide. >1 means a terminal is sharing it.
	var pids [2]uint32
	n, _, _ := kernel32.NewProc("GetConsoleProcessList").Call(
		uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	if n != 1 {
		return
	}

	const swHide = 0
	user32 := windows.NewLazySystemDLL("user32.dll")
	_, _, _ = user32.NewProc("ShowWindow").Call(hwnd, swHide)
}
