        .global _start
_start:

main:
        cmpl $(target - . - 5), %eax
	jmp main

target:
        mov $0, %rax
        mov %rbx, (%rax)
