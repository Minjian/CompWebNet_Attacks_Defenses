#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void nmemcpy(char *out, int outl, char *in, int inl) {
  int len = inl;

  if (len > outl) {
    len = outl;
  }

  for (int i = 0; i <= len; i++) {
    out[i] = in[i];
  }
}

void bar(char *arg, int len) {
  char buf[128];
  nmemcpy(buf, sizeof buf, arg, len);
}

void foo(char *arg, int len) {
  long *p;
  long a = 0;
  p = &a;

  bar(arg, len);

  *p = a;

  _exit(0);
  /* not reached */
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "target4: argc != 2\n");
    exit(EXIT_FAILURE);
  }

  FILE *f = fopen(argv[1], "r");
  if (!f) {
    perror("target4 fopen failed");
    exit(EXIT_FAILURE);
  }

  char input[65536];
  size_t len = fread(input, 1, sizeof(input), f);
  if (!len) {
    perror("target4 fread error");
    exit(EXIT_FAILURE);
  }

  setuid(0);
  foo(input, len);
  return 0;
}
