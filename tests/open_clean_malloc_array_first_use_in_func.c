#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#define SIZE 512
#define FILES 3

int main() {

  int * files = malloc(sizeof(int) * FILES);
  if (!files)
    return EXIT_FAILURE;

  for (int i = 0; i < FILES; i++) {
    files[i] = open("./files.txt", O_RDWR); 
  }

  char buffer[SIZE];
  for (int i = 0; i < FILES; i++) {
    if (files[i] == -1)
      continue;

    ssize_t r = read(files[i], buffer, SIZE-1); 
    if (r == -1) {
      printf("Could not read from file\n");
      continue;
    }
    printf("%.*s", SIZE-1, buffer);
  }

  free(files);
  return EXIT_SUCCESS;
}
