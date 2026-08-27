//go:build !windows

package app

import "syscall"

func runningAsService() bool { return false }

func windowsRestartAttr() *syscall.SysProcAttr { return nil }
