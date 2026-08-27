//go:build !windows

package main

import (
	"fmt"
	"os"
)

func runUnderServiceManager(_ string) (handled bool, err error) {
	return false, nil
}

func runServiceCommand(_ []string) int {
	fmt.Fprintln(os.Stderr, "service management is only supported on Windows")
	return 2
}
