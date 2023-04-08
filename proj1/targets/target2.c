#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void nmemcpy(char *out, int outl, char *in, int inl) {
  int len = inl;

  if (inl > outl)
    len = outl;

  for (int i = 0; i <= len; i++)
    out[i] = in[i];
}

void bar(char *arg, size_t len) {
  char buf[128];
  nmemcpy(buf, sizeof buf, arg, len);
}

void foo(char *input, size_t len) {
  bar(input, len);
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "target2: argc != 2\n");
    exit(EXIT_FAILURE);
  }

  FILE *f = fopen(argv[1], "r");
  if (!f) {
    perror("target2: fopen failed");
    exit(EXIT_FAILURE);
  }

  char input[520];
  size_t len = fread(input, 1, sizeof(input), f);
  if (!len) {
    perror("target2: fread failed");
    exit(EXIT_FAILURE);
  }

  setuid(0);
  foo(input, len);
  return 0;
}
