#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_INPUT "/tmp/sploit5_output"

char* get_shell() {
  return "/bin/sh";
}

int bar(char *arg, char *out, size_t n) {
  memcpy(out, arg, n);
  return 0;
}

void foo(char input[], size_t n) {
  char buf[256];
  bar(input, buf, n);
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "target5: argc != 2\n");
    exit(EXIT_FAILURE);
  }

  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) {
    perror("target5: open error");
    exit(EXIT_FAILURE);
  }

  char input[4096];
  ssize_t len = read(fd, input, sizeof(input));
  if (len < 0) {
    perror("target5: read failed");
    exit(EXIT_FAILURE);
  }

  setuid(0);
  foo(input, len);
  return 0;
}
