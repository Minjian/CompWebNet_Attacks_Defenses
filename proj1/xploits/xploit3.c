#include <string.h>
#include <unistd.h>
#include "shellcode.h"
#include "write_xploit.h"

#define TARGET "/tmp/target3"
#define DEFAULT_FILE "/tmp/xploit3_output"
#define SIZE 24024

int main(void)
{
  // This exploit will likely require more memory than fits on the stack
  size_t exploit_size = 0;  // TODO determine exploit size
  char *exploit = malloc(exploit_size);

  // TODO fill exploit buffer

  // Write xploit buffer to file
  write_xploit(exploit, exploit_size, DEFAULT_FILE);

  char *args[] = { TARGET, DEFAULT_FILE, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  perror("execve failed");
  fprintf(stderr, "try running \"sudo make install\" in the targets directory\n");

  return 0;
}
