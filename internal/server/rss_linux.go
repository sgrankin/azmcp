//go:build linux

package server

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func residentBytes(pid int) (uint64, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 2 {
		return 0, fmt.Errorf("invalid process memory record")
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, err
	}
	return pages * uint64(os.Getpagesize()), nil
}
