#include "exec_darwin.h"

extern char** environ;

int
fork_exec(char *argv0, char **argv, int size,
		mach_port_name_t *task,
		mach_port_t *port_set,
		mach_port_t *exception_port,
		mach_port_t *notification_port)
{
	kern_return_t kret;
	pid_t pid = vfork();
	if (pid > 0) {
		// In parent.
		kret = acquire_mach_task(pid, task, port_set, exception_port, notification_port);
		if (kret != KERN_SUCCESS) return -1;

		return pid;
	}

	// In child.
	int pret;

	// Create a new process group.
	if (setpgid(0, 0) < 0) {
		return -1;
	}

	// Set errno to zero before a call to ptrace.
	// It is documented that ptrace can return -1 even
	// for successful calls.
	errno = 0;
	pret = ptrace(PT_TRACE_ME, 0, 0, 0);
	if (pret != 0 && errno != 0) return -errno;

	errno = 0;
	pret = ptrace(PT_SIGEXC, 0, 0, 0);
	if (pret != 0 && errno != 0) return -errno;

	// Create the child process.
	execve(argv0, argv, environ);

	// We should never reach here, but if we did something went wrong.
	exit(1);
}
