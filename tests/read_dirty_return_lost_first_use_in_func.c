#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#define SIZE 512

int main(int argc, char *argv[]) {

  int fd = open("./file.txt", O_RDWR);
  if (fd == -1)
    return EXIT_FAILURE;

  char buffer[SIZE];

  // Error should be reported here
  read(fd, buffer, SIZE-1);

  printf("%.*s", SIZE-1, buffer);
  return EXIT_SUCCESS;
}
