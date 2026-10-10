//go:build darwin

package server

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// proc_taskinfo is the fixed PROC_PIDTASKINFO structure in Darwin's proc_info.h.
type procTaskInfo struct {
	Virtual, Resident, TotalUser, TotalSystem, ThreadsUser, ThreadsSystem                                                                uint64
	Policy, Faults, Pageins, COWFaults, MessagesSent, MessagesReceived, SyscallsMach, SyscallsUnix, CSW, ThreadNum, NumRunning, Priority int32
}

func residentBytes(pid int) (uint64, error) {
	var info procTaskInfo
	n, _, errno := syscall.Syscall6(syscall.SYS_PROC_INFO, 2, uintptr(pid), 4, 0, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	runtime.KeepAlive(&info)
	if errno != 0 {
		return 0, errno
	}
	if n != unsafe.Sizeof(info) {
		return 0, fmt.Errorf("unexpected process memory record size: %d", n)
	}
	return info.Resident, nil
}
