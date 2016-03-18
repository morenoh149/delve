#include "exec_darwin.h"

extern char** environ;

int
fork_exec(char *argv0, char **argv, int size) {
	kern_return_t kret;
	pid_t pid = vfork();
	if (pid > 0) {
		// In parent.
		return pid;
	}

	// In child.
	int pret;

	// Create a new process group.
	if (setpgid(0, 0) < 0) {
		exit(1);
	}

	// Set errno to zero before a call to ptrace.
	// It is documented that ptrace can return -1 even
	// for successful calls.
	errno = 0;
	pret = ptrace(PT_TRACE_ME, 0, 0, 0);
	if (pret != 0 && errno != 0) exit(2);

	errno = 0;
	pret = ptrace(PT_SIGEXC, 0, 0, 0);
	if (pret != 0 && errno != 0) exit(2);

	// Create the child process.
	execve(argv0, argv, environ);

	// We should never reach here, but if we did something went wrong.
	exit(3);
}
