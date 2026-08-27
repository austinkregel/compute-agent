//go:build windows

package app

import (
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// runningAsService reports whether the process was started by the Windows SCM.
func runningAsService() bool {
	isSvc, err := svc.IsWindowsService()
	return err == nil && isSvc
}

// windowsRestartAttr puts a respawned agent in its own process group so a
// console signal to the parent doesn't take it down.
func windowsRestartAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
}
