//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "aiguard-service.exe 只能在 Windows 上运行")
	os.Exit(1)
}
