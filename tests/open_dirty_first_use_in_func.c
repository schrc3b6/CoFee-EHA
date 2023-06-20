#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#define SIZE 512

int main() {

  int fd = open("./test.txt", O_RDWR); 

  char buffer[SIZE];
  // Should report an error here
  ssize_t r = read(fd, buffer, SIZE-1);
  if (r == -1)
    return EXIT_FAILURE;

  printf("%.*s", SIZE-1, buffer);
  return EXIT_SUCCESS;
}
