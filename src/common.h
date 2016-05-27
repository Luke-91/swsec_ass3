#include <stdio.h>

void fail(const char *msg) {
    fprintf(stderr, "Aborting: %s\n", msg);
    exit(EXIT_SUCCESS);
}
