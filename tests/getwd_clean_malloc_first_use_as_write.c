#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    char * buffer = malloc(sizeof(char) * 512);
    if (buffer == NULL) { return -1; }

    char * buf_2 = getwd(buffer);
    if (buf_2 == NULL) { 
	    free(buffer);
	    return -1; 
    }

    buffer[0] = 42;

    free(buffer);
    return 0;
}
