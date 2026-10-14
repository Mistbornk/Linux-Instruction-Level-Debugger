#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

int main(int argc, char** argv) {
    if (argc != 2)
        return 2;
    char* end;
    long value = strtol(argv[1], &end, 10);
    if (*end || value <= 1 || value > 2147483647)
        return 2;
    const pid_t pid = (pid_t)value;
    if (ptrace(PTRACE_SEIZE, pid, NULL, NULL) == -1) {
        perror("SEIZE");
        return 3;
    }
    if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) == -1) {
        perror("INTERRUPT");
        return 4;
    }
    int status;
    if (waitpid(pid, &status, __WALL) != pid || !WIFSTOPPED(status))
        return 5;
    int failed = 0;
    for (unsigned i = 0; i < 8; ++i) {
        if (i == 4 || i == 5)
            continue;
        errno = 0;
        const long reg =
            ptrace(PTRACE_PEEKUSER, pid,
                   (void*)(offsetof(struct user, u_debugreg) + i * sizeof(unsigned long)), NULL);
        if (reg == -1 && errno) {
            perror("PEEKUSER");
            failed = 6;
            break;
        }
        printf("DR%u=%lx\n", i, (unsigned long)reg);
    }
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("DETACH");
        return 7;
    }
    return failed;
}
