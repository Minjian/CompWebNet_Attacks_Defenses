# tools
CC := gcc
RM := rm -f 

# flags
CFLAGS := -ggdb -m64
LDFLAGS := -m64
LDLIBS :=

# sources
sources := xploit1.c xploit2.c xploit3.c xploit4.c xploit5.c run-shellcode.c
targets := $(sources:.c=)

# gmake magic
.PHONY: default all clean

# targets
default: all
all: $(targets) shellcode.bin

clean:
	$(RM) $(targets) $(sources:.c=.o) shellcode.bin

%.o: %.S | bin
	$(CC) -m64 -c -o $@ $<

%.bin: %.o
	objcopy -S -O binary -j .text $< $@

# dependencies
$(sources:.c=.o): shellcode.h
