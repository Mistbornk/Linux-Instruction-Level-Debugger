#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

extern char** environ;

static int failure(const char* operation) {
    perror(operation);
    return 1;
}

// Execute an existing test fixture from anonymous, file-backed ELF storage.
// The helper never launches a shell or an unrelated process.
int main(int argc, char** argv) {
    if (argc != 3) {
        fputs("usage: elf_memfd <fixture> <mode>\n", stderr);
        return 2;
    }
    const int source = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (source == -1)
        return failure("open fixture");
    const int executable = memfd_create("sdb-elf-image", MFD_CLOEXEC);
    if (executable == -1)
        return failure("memfd_create");
    char bytes[4096];
    for (;;) {
        ssize_t count = read(source, bytes, sizeof(bytes));
        if (count == -1 && errno == EINTR)
            continue;
        if (count == -1)
            return failure("read fixture");
        if (count == 0)
            break;
        ssize_t done = 0;
        while (done < count) {
            const ssize_t written = write(executable, bytes + done, (size_t)(count - done));
            if (written == -1 && errno == EINTR)
                continue;
            if (written <= 0) {
                if (written == 0)
                    errno = EIO;
                return failure("write memfd");
            }
            done += written;
        }
    }
    if (close(source) == -1)
        return failure("close fixture");
    if (fchmod(executable, 0700) == -1)
        return failure("chmod memfd");
    char* arguments[] = {argv[1], argv[2], NULL};
    fexecve(executable, arguments, environ);
    return failure("fexecve");
}
