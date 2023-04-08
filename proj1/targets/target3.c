#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct widget_t {
  double x;
  double y;
  long count;
};

#define MAX_WIDGETS 1000

int foo(char *in, long count) {
  struct widget_t buf[MAX_WIDGETS];

  if (count < MAX_WIDGETS) {
    memcpy(buf, in, count * sizeof(struct widget_t));
  }

  return 0;
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "target3: argc != 2\n");
    exit(EXIT_FAILURE);
  }

  /*
   * format of file at argv[1] is as follows:
   *
   * - a count, encoded as a decimal number in ASCII
   * - a comma (",")
   * - the remainder of the data, treated as an array
   *   of struct widget_t
   */

  FILE *f = fopen(argv[1], "r");
  if (!f) {
    perror("target3: fopen failed");
    exit(EXIT_FAILURE);
  }

  char input[65536];
  size_t len = fread(input, 1, sizeof(input), f);
  if (!len) {
    perror("target3: fread error");
    exit(EXIT_FAILURE);
  }

  long count;
  char *in;

  count = (long)strtoul(input, &in, 10);
  if (*in != ',') {
    fprintf(stderr, "target3: argument format is [count],[data]\n");
    exit(EXIT_FAILURE);
  }
  in++;    /* advance one byte, past the comma */

  setuid(0);
  foo(in, count);

  return 0;
}
