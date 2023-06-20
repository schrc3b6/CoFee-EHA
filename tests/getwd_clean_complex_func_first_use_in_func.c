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
    if (!ret) {
      free(buf);
      perror("Error getting the current directory");
      return NULL;
    }
  }

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
