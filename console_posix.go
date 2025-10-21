//go:build !windows
// +build !windows

package main

// Non-Windows: nothing to do.
func enableWindowsANSI() error { return nil }
