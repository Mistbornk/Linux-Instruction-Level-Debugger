#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t handled;
static volatile int visits;

static void handler(int signo) {
    handled += signo == SIGUSR1;
}

__attribute__((noinline)) void tick(void) {
    ++visits;
}

extern void notify_signal(void);
__asm__(".text\n"
        ".global notify_signal, signal_call\n"
        ".type notify_signal, @function\n"
        "notify_signal:\n"
        "mov $39, %eax\n" /* getpid */
        "syscall\n"
        "mov %eax, %edi\n"
        "mov $10, %esi\n" /* SIGUSR1 */
        "mov $62, %eax\n" /* kill */
        "signal_call:\n"
        "syscall\n"
        "ret\n"
        ".size notify_signal, .-notify_signal\n");

int main(int argc, char** argv) {
    if (argc > 1 && strcmp(argv[1], "usr1") == 0) {
        signal(SIGUSR1, handler);
        raise(SIGUSR1);
        printf("HANDLED=%d\n", (int)handled);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "break-signal") == 0) {
        signal(SIGUSR1, handler);
        notify_signal();
        printf("HANDLED=%d\n", (int)handled);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "segv") == 0) {
        __asm__ volatile("xor %%eax, %%eax\n\tmovl $1, (%%rax)" ::: "rax", "memory");
        return 77;
    }
    if (argc > 1 && strcmp(argv[1], "ill") == 0) {
        __asm__ volatile("ud2");
        return 77;
    }
    if (argc > 1 && strcmp(argv[1], "trap") == 0) {
        raise(SIGTRAP);
        return 77;
    }
    if (argc > 1 && strcmp(argv[1], "int3") == 0) {
        __asm__ volatile("int3");
        return 77;
    }
    if (argc > 1 && strcmp(argv[1], "args") == 0) {
        for (int i = 2; i < argc; ++i)
            printf("ARG[%d]=%s\n", i - 2, argv[i]);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "exec") == 0) {
        execl("/bin/true", "true", (char*)0);
        return 77;
    }
    for (int i = 0; i < 10; ++i)
        tick();
    printf("VISITS=%d\n", visits);
    return visits != 10;
}
