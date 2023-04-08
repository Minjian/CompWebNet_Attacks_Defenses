#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_INPUT "/tmp/sploit1_output"

int bar(char *arg, char *out) {
  strcpy(out, arg);
  return 0;
}

void foo(char input[]) {
  char buf[256];
  bar(input, buf);
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "target1: argc != 2\n");
    exit(EXIT_FAILURE);
  }

  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) {
    perror("target1: open error");
    exit(EXIT_FAILURE);
  }

  char input[4096];
  if (read(fd, input, sizeof(input)) < 0) {
    perror("target1: read failed");
    exit(EXIT_FAILURE);
  }

  setuid(0);
  foo(input);
  return 0;
}
