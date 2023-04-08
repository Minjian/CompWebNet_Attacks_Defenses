#include <stdio.h>
#include <stdlib.h>

int write_xploit(char *xploit, size_t len, char *filename) {
  FILE *f = fopen(filename, "w");
  if (!f) {
    perror("fopen error");
    exit(EXIT_FAILURE);
  }
  
  size_t bytes_written = fwrite(xploit, 1, len, f);
  if (bytes_written != len) {
    fprintf(stderr, "fwrite wrote %zu bytes. expected %zu\n", bytes_written, len);
    exit(EXIT_FAILURE);
  }

  if (fclose(f)) {
    perror("fclose error");
    exit(EXIT_FAILURE);
  }

}
