#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>



char * mywdfunc(unsigned int bufsize) {
  if (bufsize < 100) {
    return NULL;
  }

  char * buf = (char *) malloc(sizeof(char) * bufsize);
  char * ret;
  if (buf) {
    ret = getwd(buf); 
  }

  // Error should be returned here
  return buf;
}


int main() {

  char * ret = mywdfunc(512);
  if (!ret)
    return EXIT_FAILURE;

  printf("%s", ret);
  free(ret);
  return EXIT_SUCCESS;
}
