# tools
CC := gcc
RM := rm -f

# flags
CFLAGS := -ggdb -m64 -g -std=c99 -D_GNU_SOURCE -fno-stack-protector -mpreferred-stack-boundary=3 -Wno-format-security
LDFLAGS := -m64 -z execstack

# sources
sources := target1.c target2.c target3.c target4.c
targets := $(sources:%.c=%)

# gmake magic
.PHONY: default install clean

# targets
default: $(targets) target5

install: $(targets) target5
	install -o root -t /tmp $(targets) target5
	chmod 4755 /tmp/target*

%: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

%.o: %.S
	$(CC) $< -c -o $@ $(CFLAGS)

# Disable executable stack for target5
target5.o: LDFLAGS := -m64
target5.o: target5.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -c -o $@

target5: CC := musl-gcc
target5: LDFLAGS := -m64
target5: target5.o
	$(CC) -static $(LDFLAGS) $^ -o $@ -Wl,--whole-archive

clean:
	$(RM) $(targets) $(targets:%=%.o) target5 target5.o
