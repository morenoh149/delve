package proc

import (
	"os"
	"syscall"
	"unsafe"
)

func forkExec(argv0 string, argv []string, env []string) int {
	argv0b, err := syscall.BytePtrFromString(argv0)
	if err != nil {
		return 0
	}
	argvb, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		return 0
	}
	envb, err := syscall.SlicePtrFromStrings(env)
	if err != nil {
		return 0
	}
	r1, r2, err1 := syscall.RawSyscall(syscall.SYS_FORK, 0, 0, 0)
	if err1 != 0 {
		return 0
	}
	if r2 == 0 {
		// In parent.
		return int(r1)
	}
	_, _, err1 = syscall.RawSyscall(syscall.SYS_PTRACE, uintptr(syscall.PTRACE_TRACEME), 0, 0)
	if err1 != 0 {
		os.Exit(2)
	}
	_, _, err1 = syscall.RawSyscall(syscall.SYS_PTRACE, uintptr(syscall.PT_SIGEXC), 0, 0)
	if err1 != 0 {
		os.Exit(3)
	}
	_, _, err1 = syscall.RawSyscall(syscall.SYS_SETSID, 0, 0, 0)
	if err1 != 0 {
		os.Exit(4)
	}
	_, _, err1 = syscall.RawSyscall(syscall.SYS_EXECVE,
		uintptr(unsafe.Pointer(argv0b)),
		uintptr(unsafe.Pointer(&argvb[0])),
		uintptr(unsafe.Pointer(&envb[0])))
	if err1 != 0 {
		os.Exit(5)
	}
	return 0
}
