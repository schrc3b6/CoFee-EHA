#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    char buffer[512];

    char * buf_2 = getwd(buffer);

    // Error should be reported here
    printf("%s", buffer);
    
    return 0;
}
