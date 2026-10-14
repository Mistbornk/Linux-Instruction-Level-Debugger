#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

_Alignas(8) volatile uint64_t watched[8] = {0};
static volatile sig_atomic_t finish = 0;
static volatile sig_atomic_t handled = 0;
static atomic_uint visits = 0;
static pthread_barrier_t barrier;

__attribute__((noinline)) void ready(void) {
    __asm__ volatile("nop" ::: "memory");
}
__attribute__((noinline)) void shared_site(void) {
    atomic_fetch_add_explicit(&visits, 1, memory_order_relaxed);
}
__attribute__((noinline)) void bt_leaf(void) {
    __asm__ volatile(".globl bt_site\nbt_site:\nnop" ::: "memory");
}
__attribute__((noinline)) void bt_middle(void) {
    bt_leaf();
    __asm__ volatile("nop");
}
__attribute__((noinline)) void bt_outer(void) {
    bt_middle();
    __asm__ volatile("nop");
}

static void finish_signal(int number) {
    (void)number;
    finish = 1;
}
static void count_signal(int number) {
    (void)number;
    ++handled;
}
static void* worker(void* arg) {
    const uintptr_t index = (uintptr_t)arg;
    pthread_barrier_wait(&barrier);
    for (unsigned i = 0; i < 6; ++i) {
        shared_site();
        watched[index] = i + 1; // each worker owns a distinct scalar object
    }
    if (index == 1)
        raise(SIGUSR2);
    return NULL;
}
static void* attach_worker(void* arg) {
    (void)arg;
    while (!finish) {
        shared_site();
        usleep(1000);
    }
    return NULL;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2)
        return 2;
    if (!strcmp(argv[1], "memory")) {
        ready();
        printf("VALUE=%llu\n", (unsigned long long)watched[0]);
    } else if (!strcmp(argv[1], "watch")) {
        ready();
        __asm__ volatile(".globl watched_store\nwatched_store:\nmovq $11, watched(%%rip)" ::
                             : "memory");
        __asm__ volatile(".globl after_first_write\nafter_first_write:\nnop" ::: "memory");
        const uint64_t value = watched[0];
        __asm__ volatile(".globl after_watch_read\nafter_watch_read:\nnop" ::: "memory");
        watched[0] = value + 1;
        printf("WATCHED=%llu\n", (unsigned long long)watched[0]);
    } else if (!strcmp(argv[1], "backtrace")) {
        bt_outer();
    } else if (!strcmp(argv[1], "threads")) {
        signal(SIGUSR2, count_signal);
        if (pthread_barrier_init(&barrier, NULL, 3))
            return 3;
        pthread_t threads[2];
        for (uintptr_t i = 0; i < 2; ++i)
            if (pthread_create(&threads[i], NULL, worker, (void*)i))
                return 4;
        pthread_barrier_wait(&barrier);
        for (unsigned i = 0; i < 2; ++i)
            if (pthread_join(threads[i], NULL))
                return 5;
        pthread_barrier_destroy(&barrier);
        printf("THREAD_VISITS=%u HANDLED=%d\n", atomic_load(&visits), handled);
    } else if (!strcmp(argv[1], "attach")) {
        // This isolated, test-owned process explicitly permits sibling tracers
        // under Yama ptrace_scope=1; the harness never changes host policy.
        if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) == -1)
            return 6;
        signal(SIGUSR1, finish_signal);
        pthread_t thread;
        if (argc > 2 && pthread_create(&thread, NULL, attach_worker, NULL))
            return 7;
        printf("ATTACH_READY=%ld\n", (long)getpid());
        while (!finish) {
            shared_site();
            usleep(1000);
        }
        if (argc > 2 && pthread_join(thread, NULL))
            return 8;
        printf("ATTACH_DONE=%u\n", atomic_load(&visits));
    } else if (!strcmp(argv[1], "syscalls")) {
        ready();
        const long fd = syscall(SYS_openat, AT_FDCWD, "/dev/null", O_WRONLY, 0);
        if (fd < 0)
            return 9;
        if (syscall(SYS_write, fd, "hello", 5) != 5)
            return 10;
        if (syscall(SYS_close, fd))
            return 11;
        errno = 0;
        if (syscall(SYS_openat, AT_FDCWD, (void*)1, O_RDONLY, 0) != -1 || errno != EFAULT)
            return 12;
        puts("SYSCALLS_DONE");
    } else if (!strcmp(argv[1], "fork")) {
        const pid_t child = fork();
        if (child == -1)
            return 14;
        if (child == 0) {
            shared_site();
            watched[0] = 1;
            puts("FORK_CHILD_OK");
            _exit(0);
        }
        shared_site();
        watched[0] = 2;
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
            return 15;
        puts("FORK_PARENT_OK");
    } else
        return 13;
    return 0;
}
