CC=gcc
CCFLAGS= -std=c11 -I. -g -Wall 
LDFLAGS= -lcrypto
TARGETS := trace.exe handler.o app.exe
SRC := trace.c bpf_elf.c perf_buffer.c uid.c \
	bpf_syscall_helpers.c read_note.c

OBJ = $(SRC:.c=.o)

.PHONY: all clean
all: $(TARGETS)
clean:
	rm -f $(TARGETS) $(OBJ)
handler.o: handler.c
	clang -O2 -emit-llvm -Wall -c -target bpf $< -o - | llc -march=bpf -filetype=obj -o $@
trace.exe: $(OBJ) $(SRC:.c=.h)
	$(CC) $(CCFLAGS) $(LDFLAGS) -o $@ $(OBJ)
	sudo chown root $@
	sudo chmod u+s $@
app.exe: app.c
	$(CC) $(CCFLAGS) -o $@ app.c
