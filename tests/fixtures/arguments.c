#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    for (int i = 0; i < argc; ++i)
        printf("ARG[%d]=%zu:%s\n", i, strlen(argv[i]), argv[i]);
    return 0;
}
