#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

_Atomic int gate = 0;
_Atomic int wake_allowed = 0;

static void* wait_for_peer(void* unused) {
    (void)unused;
    register long fourth __asm__("r10") = 0;
    register long fifth __asm__("r8") = 0;
    register long sixth __asm__("r9") = 0;
    long result;
    __asm__ volatile(".globl futex_wait_call\nfutex_wait_call:\nsyscall"
                     : "=a"(result)
                     : "0"(SYS_futex), "D"(&gate), "S"(FUTEX_WAIT_PRIVATE), "d"(0), "r"(fourth),
                       "r"(fifth), "r"(sixth)
                     : "rcx", "r11", "memory");
    return (void*)(result == 0 || result == -EAGAIN ? 0L : 1L);
}

int main(void) {
    pthread_t worker;
    if (pthread_create(&worker, NULL, wait_for_peer, NULL))
        return 2;
    // The debugger sets this only after hitting the worker's syscall instruction.
    // Until it resumes peers, gate remains zero and FUTEX_WAIT cannot complete.
    while (!atomic_load_explicit(&wake_allowed, memory_order_acquire))
        sched_yield();
    atomic_store_explicit(&gate, 1, memory_order_release);
    if (syscall(SYS_futex, &gate, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0) < 0)
        return 3;
    void* result;
    if (pthread_join(worker, &result) || result)
        return 4;
    puts("BLOCKING_SYSCALL_DONE");
    return 0;
}
