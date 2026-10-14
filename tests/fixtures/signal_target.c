#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

_Alignas(8) volatile uint64_t watched = 0;
_Atomic int finish = 0;
static volatile sig_atomic_t requested = 0;
static volatile sig_atomic_t interrupts = 0;

__attribute__((noinline)) void cleanup_site(void) {
    __asm__ volatile("nop" ::: "memory");
}

static void request_finish(int number) {
    (void)number;
    requested = 1;
}

static void count_interrupt(int number) {
    (void)number;
    ++interrupts;
}

static void* worker(void* argument) {
    (void)argument;
    while (!atomic_load_explicit(&finish, memory_order_relaxed))
        usleep(1000);
    return NULL;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    // The fixture is owned by the test and permits its sibling debugger/probe.
    if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) == -1)
        return 2;
    struct sigaction action = {0};
    sigemptyset(&action.sa_mask);
    action.sa_handler = request_finish;
    if (sigaction(SIGUSR1, &action, NULL) == -1)
        return 3;
    action.sa_handler = count_interrupt;
    if (sigaction(SIGINT, &action, NULL) == -1)
        return 4;
    const int threaded = argc == 2 && strcmp(argv[1], "threads") == 0;
    pthread_t threads[2];
    for (int i = 0; i < (threaded ? 2 : 0); ++i)
        if (pthread_create(&threads[i], NULL, worker, NULL))
            return 5;
    printf("SIGNAL_READY=%ld\n", (long)getpid());
    while (!requested && !atomic_load_explicit(&finish, memory_order_relaxed))
        usleep(1000);
    atomic_store_explicit(&finish, 1, memory_order_relaxed);
    for (int i = 0; i < (threaded ? 2 : 0); ++i)
        if (pthread_join(threads[i], NULL))
            return 6;
    // Signal-driven detach must restore both modifications before the target
    // runs here. A leftover INT3 or hardware watch generates an unhandled trap.
    cleanup_site();
    watched = 42;
    printf("SIGNAL_DONE=%llu INTERRUPTS=%d\n", (unsigned long long)watched, interrupts);
    return 0;
}
