import (
	"os"
	"syscall"
	"unsafe"
)

func forkExec(argv0 string, argv []string, env []string) (int, error) {
	argv0b, err := syscall.BytePtrFromString(argv0)
	if err != nil {
		return 0, err
	}
	argvb, err := syscall.BytePtrFromStrings(argv)
	if err != nil {
		return 0, err
	}
	envb, err := syscall.BytePtrFromStrings(env)
	if err != nil {
		return 0, err
	}
	r1, r2, err1 = syscall.RawSyscall(syscall.SYS_FORK, 0, 0, 0)
	if err1 != 0 {
		return 0, err1
	}
	if r2 == 0 {
		// In parent.
		return r1, nil
	}
	_, _, err1 := syscall.RawSyscall(syscall.SYS_PTRACE, uintptr(syscall.PTRACE_TRACEME), 0, 0)
	if err1 != 0 {
		os.Exit(2)
	}
	_, _, err1 = syscall.RawSyscall(syscall.SYS_PTRACE, uintptr(syscall.PT_SIGEXEC), 0, 0)
	if err1 != 0 {
		os.Exit(2)
	}
	_, _, err1 = syscall.RawSyscall(syscall.SYS_SETSID, 0, 0, 0)
	if err1 != 0 {
		os.Exit(2)
	}
	_, _, err1 = syscall.RawSyscall(syscall.SYS_SETPGID, 0, 0, 0)
	if err1 != 0 {
		os.Exit(2)
	}
	_, _, err1 = syscall.RawSyscall(syscall.SYS_EXECVE,
		uintptr(unsafe.Pointer(argv0b)),
		uintptr(unsafe.Pointer(&argvb[0])),
		uintptr(unsafe.Pointer(&envb[0])))
	if err1 != 0 {
		os.Exit(3)
	}
}
