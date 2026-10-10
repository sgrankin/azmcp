//go:build !darwin && !linux

package server

import "errors"

func residentBytes(pid int) (uint64, error) {
	return 0, errors.New("worker memory monitoring requires macOS or Linux")
}
