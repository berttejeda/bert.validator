//go:build windows
// +build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// Turn on ANSI (VT) processing for Windows consoles (best-effort).
func enableWindowsANSI() error {
	handles := []windows.Handle{
		windows.Handle(os.Stdout.Fd()),
		windows.Handle(os.Stderr.Fd()),
	}
	for _, h := range handles {
		var mode uint32
		if err := windows.GetConsoleMode(h, &mode); err != nil {
			// Not a console or unsupported; skip.
			continue
		}
		mode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
		_ = windows.SetConsoleMode(h, mode) // best effort
	}
	return nil
}
