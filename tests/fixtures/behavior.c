#include <signal.h>
#include <stdio.h>
#include <unistd.h>
static volatile sig_atomic_t handled;
static void handler(int signal) { handled = signal; }
int main(void) {
#if MODE == 1
    signal(SIGUSR1, handler);
    raise(SIGUSR1);
    printf("HANDLED=%d\n", (int)handled);
#elif MODE == 2
    __asm__ volatile("ud2");
#elif MODE == 3
    __asm__ volatile("int3");
#elif MODE == 4
    execl("/bin/true", "true", (char*)0);
    return 77;
#else
    printf("NORMAL=1\n");
#endif
    return 0;
}
