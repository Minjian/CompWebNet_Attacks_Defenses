#include <string.h>
#include <unistd.h>
#include "shellcode.h"
#include "write_xploit.h"

#define TARGET "/tmp/target5"
#define DEFAULT_OUTPUT "/tmp/xploit5_output"

int main(int argc, char *argv[])
{
  // TODO determine exploit length
  char exploit[0];

  // TODO fill exploit buffer

  // Write the exploit buffer to a file
  write_xploit(exploit, sizeof(exploit), DEFAULT_OUTPUT);

  char *args[] = { TARGET, DEFAULT_OUTPUT, NULL };
  char *env[] = { NULL };
  execve(TARGET, args, env);
  perror("execve failed");

  return 0;
}
