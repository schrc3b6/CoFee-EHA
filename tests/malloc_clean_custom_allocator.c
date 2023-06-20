#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#define SIZE 128

char * myalloc(unsigned int size) {
  if (size > 512)
    return NULL;

  return malloc(sizeof(char) * size);
}

int main(int argc, char *argv[]) {

  char * mem = myalloc(SIZE);
  if (!mem)
    return EXIT_FAILURE;

  ssize_t num = read(STDIN_FILENO, mem, SIZE-1);
  if (num == -1)
    return EXIT_FAILURE;

  printf("%c", mem[0]);
  free(mem);
  return EXIT_SUCCESS;
}
