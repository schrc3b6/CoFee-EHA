#include <stdlib.h>
#include <unistd.h>

int main() {
    char buffer[512];

    char * buf_2 = getwd(buffer);
    if (buf_2 == NULL) { return -1; }

    buffer[0] = 42;

    return 0;
}
