CC=gcc
CCFLAGS= -std=c11 -I. -g -Wall
TARGETS := trace handler.o app
.PHONY: all clean
all: $(TARGETS)
clean:
	rm $(TARGETS)
handler.o: handler.c
	clang -O2 -emit-llvm -Wall -c -target bpf $< -o - | llc -march=bpf -filetype=obj -o $@
trace: trace.c bpf_elf.c bpf_elf.h perf_buffer.c perf_buffer.h uid.h uid.c \
	bpf_syscall_helpers.c bpf_syscall_helpers.h read_note.h read_note.c
	$(CC) $(CCFLAGS) -o trace trace.c bpf_elf.c perf_buffer.c \
	bpf_syscall_helpers.c read_note.c uid.c
	sudo chown root trace
	sudo chmod u+s trace
app: app.c
	$(CC) $(CCFLAGS) -o app app.c  
