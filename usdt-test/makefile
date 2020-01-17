CC=gcc
CCFLAGS= -std=c11 -I. -g -Wall
TARGETS := trace.exe attach.exe t.exe

.PHONY: all clean
all: $(TARGETS)
clean:
	rm -f $(TARGETS)
trace.exe: trace.c
	$(CC) $(CCFLAGS) -o $@ $^
attach.exe: attach.c
	$(CC) $(CCFLAGS) -o $@ $^
t.exe: t.s
	as -o t.o t.s
	ld -o t.exe t.o
