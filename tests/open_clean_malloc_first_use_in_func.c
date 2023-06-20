#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#define SIZE 512

int main() {

  int fd = open("./test.txt", O_RDWR); 
  if (fd == -1)
    return EXIT_FAILURE;

  char * buffer = (char *) malloc(sizeof(char) * SIZE);
  if (!buffer)
    return EXIT_FAILURE;
  
  ssize_t r = read(fd, buffer, SIZE-1);
  if (r == -1) {
    free(buffer);
    return EXIT_FAILURE;
  }

  printf("%.*s", SIZE-1, buffer);
  free(buffer);
  return EXIT_SUCCESS;
}
