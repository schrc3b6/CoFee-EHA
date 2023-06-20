#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define SIZE 512

int main(int argc, char *argv[]) {

  int fd = open("./file.txt", O_RDWR); 
  if (fd == -1)
    return -1;

  char buffer[SIZE];

  // Checking wrong error value by mistake
  while (read(fd, buffer, 12) != 0) {
    // Error should be returned here
    printf("%.*s", 12, buffer);
  }

  return EXIT_SUCCESS;
}
