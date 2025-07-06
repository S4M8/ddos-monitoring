//go:build !windows
// +build !windows

package main

import "os"

func isElevated() bool {
    return os.Geteuid() == 0
}
