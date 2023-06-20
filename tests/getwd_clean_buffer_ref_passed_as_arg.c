#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>


// Seems not to be working when the variable that we want to track is not returned
// but stored into a buffer passed as an argument.
char * mywdfunc(char ** buffer, unsigned int bufsize) {
  *buffer = malloc(sizeof(char) * bufsize);
  
  char * retVal = NULL;
  
  if (*buffer)
    retVal = getwd(*buffer);
  
  return retVal;
}


int main() {

    char * buf = NULL;
    char * ret = mywdfunc(&buf, 512); 

    if (!ret) {
      return EXIT_FAILURE;
    }

    printf("%s", buf);
    free(buf);
    return EXIT_SUCCESS;
}
