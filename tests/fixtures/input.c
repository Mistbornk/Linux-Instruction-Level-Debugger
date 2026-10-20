#include <string.h>
#include <unistd.h>

int main(void) {
    char buffer[64];
    size_t count = 0;
    // Consume exactly one line; subsequent bytes still belong to the debugger.
    while (count < sizeof(buffer)) {
        if (read(STDIN_FILENO, buffer + count, 1) != 1)
            return 2;
        if (buffer[count] == '\n')
            break;
        ++count;
    }
    if (count != 5 || memcmp(buffer, "hello", 5) != 0)
        return 3;
    return write(STDOUT_FILENO, "INPUT=hello\n", 12) == 12 ? 0 : 4;
}
