	.file ""
	.section .rodata.cst8,"a",@progbits
	.align	16
caml_negf_mask:
	.quad	0x8000000000000000
	.quad	0
	.align	16
caml_absf_mask:
	.quad	0x7fffffffffffffff
	.quad	-1
	.data
	.globl	camlA__data_begin
camlA__data_begin:
	.text
	.globl	camlA__code_begin
camlA__code_begin:
	.data
	.align	8
	.data
	.align	8
	.quad	3063
	.globl	camlA__test2_208
camlA__test2_208:
	.globl	camlA__test2_118_closure
camlA__test2_118_closure:
	.quad	camlA__test2_118
	.quad	3
	.data
	.align	8
	.quad	3063
	.globl	camlA__test1_206
camlA__test1_206:
	.globl	camlA__test1_86_closure
camlA__test1_86_closure:
	.quad	camlA__test1_86
	.quad	3
	.data
	.align	8
	.quad	4087
	.globl	camlA__h2_204
camlA__h2_204:
	.globl	camlA__h2_14_closure
camlA__h2_14_closure:
	.quad	caml_curry12
	.quad	25
	.quad	camlA__h2_14
	.data
	.align	8
	.quad	4087
	.globl	camlA__h1_205
camlA__h1_205:
	.globl	camlA__h1_65_closure
camlA__h1_65_closure:
	.quad	caml_curry2
	.quad	5
	.quad	camlA__h1_65
	.data
	.align	8
	.quad	4087
	.globl	camlA__dup_set_of_closures_366
camlA__dup_set_of_closures_366:
	.globl	camlA__probe_handler_a_256_closure
camlA__probe_handler_a_256_closure:
	.quad	caml_curry2
	.quad	5
	.quad	camlA__probe_handler_a_256
	.data
	.align	8
	.quad	4087
	.globl	camlA__dup_set_of_closures_365
camlA__dup_set_of_closures_365:
	.globl	camlA__probe_handler_a_226_closure
camlA__probe_handler_a_226_closure:
	.quad	caml_curry2
	.quad	5
	.quad	camlA__probe_handler_a_226
	.data
	.align	8
	.globl	camlA__gc_roots
camlA__gc_roots:
	.quad	0
	.text
	.align	16
	.globl	camlA__h2_14
camlA__h2_14:
	.cfi_startproc
	subq	$104, %rsp
	.cfi_adjust_cfa_offset 104
.L102:
	movq	%rax, (%rsp)
	movq	%rbx, 8(%rsp)
	movq	%rdi, 16(%rsp)
	movq	%rsi, 24(%rsp)
	movq	%rdx, 32(%rsp)
	movq	%rcx, 40(%rsp)
	movq	%r8, 48(%rsp)
	movq	%r9, 56(%rsp)
	movq	%r12, 64(%rsp)
	movq	%r13, 72(%rsp)
	movq	112(%rsp), %rax
	movq	%rax, 80(%rsp)
	movq	120(%rsp), %rax
	movq	%rax, 88(%rsp)
	movq	camlA__const_block_54@GOTPCREL(%rip), %rdi
	movq	$1, %rbx
	movq	camlStdlib__printf__anon_fn$5bprintf$2eml$3a20$2c14$2d$2d48$5d_439_closure@GOTPCREL(%rip), %rax
	call	camlCamlinternalFormat__make_printf_4932@PLT
.L100:
	movq	%rax, %r10
	subq	$32, %rsp
	.cfi_adjust_cfa_offset 32
	movq	32(%rsp), %rax
	movq	40(%rsp), %rbx
	movq	48(%rsp), %rdi
	movq	56(%rsp), %rsi
	movq	64(%rsp), %rdx
	movq	72(%rsp), %rcx
	movq	80(%rsp), %r8
	movq	88(%rsp), %r9
	movq	96(%rsp), %r12
	movq	104(%rsp), %r13
	movq	112(%rsp), %r11
	movq	%r11, (%rsp)
	movq	120(%rsp), %r11
	movq	%r11, 8(%rsp)
	movq	%r10, 16(%rsp)
	call	caml_apply12@PLT
.L101:
	addq	$32, %rsp
	.cfi_adjust_cfa_offset -32
	addq	$104, %rsp
	.cfi_adjust_cfa_offset -104
	ret
	.cfi_adjust_cfa_offset 104
	.cfi_adjust_cfa_offset -104
	.cfi_endproc
	.type camlA__h2_14,@function
	.size camlA__h2_14,. - camlA__h2_14
	.text
	.align	16
	.globl	camlA__h1_65
camlA__h1_65:
	.cfi_startproc
	subq	$24, %rsp
	.cfi_adjust_cfa_offset 24
.L105:
	movq	%rax, (%rsp)
	movq	%rbx, 8(%rsp)
	movq	camlA__const_block_75@GOTPCREL(%rip), %rdi
	movq	$1, %rbx
	movq	camlStdlib__printf__anon_fn$5bprintf$2eml$3a20$2c14$2d$2d48$5d_439_closure@GOTPCREL(%rip), %rax
	call	camlCamlinternalFormat__make_printf_4932@PLT
.L103:
	movq	%rax, %rdi
	movq	(%rsp), %rax
	movq	8(%rsp), %rbx
	addq	$24, %rsp
	.cfi_adjust_cfa_offset -24
	jmp	caml_apply2@PLT
	.cfi_adjust_cfa_offset 24
	.cfi_adjust_cfa_offset -24
	.cfi_endproc
	.type camlA__h1_65,@function
	.size camlA__h1_65,. - camlA__h1_65
	.text
	.align	16
	.globl	camlA__test1_86
camlA__test1_86:
	.cfi_startproc
	subq	$8, %rsp
	.cfi_adjust_cfa_offset 8
.L108:
	movq	%rax, (%rsp)
	movq	camlA__h1_65_closure@GOTPCREL(%rip), %rbx
	cmpl	$(camlA__probe_wrapper_0 - .), %eax
.L109:
	nop
	movq	camlA__const_block_107@GOTPCREL(%rip), %rdi
	movq	$1, %rbx
	movq	camlStdlib__printf__anon_fn$5bprintf$2eml$3a20$2c14$2d$2d48$5d_439_closure@GOTPCREL(%rip), %rax
	call	camlCamlinternalFormat__make_printf_4932@PLT
.L106:
	movq	%rax, %rbx
	movq	(%rbx), %rdi
	movq	(%rsp), %rax
	addq	$8, %rsp
	.cfi_adjust_cfa_offset -8
	jmp	*%rdi
	.cfi_adjust_cfa_offset 8
	.cfi_adjust_cfa_offset -8
	.cfi_endproc
	.type camlA__test1_86,@function
	.size camlA__test1_86,. - camlA__test1_86
	.text
	.align	16
	.globl	camlA__probe_handler_a_226
camlA__probe_handler_a_226:
	.cfi_startproc
.L111:
	movq	camlA__const_string_98@GOTPCREL(%rip), %rax
	jmp	camlA__h1_65@PLT
	.cfi_endproc
	.type camlA__probe_handler_a_226,@function
	.size camlA__probe_handler_a_226,. - camlA__probe_handler_a_226
	.text
	.align	16
	.globl	camlA__test2_118
camlA__test2_118:
	.cfi_startproc
	subq	$8, %rsp
	.cfi_adjust_cfa_offset 8
.L114:
	movq	%rax, (%rsp)
	movq	camlA__h2_14_closure@GOTPCREL(%rip), %rbx
	cmpl	$(camlA__probe_wrapper_1 - .), %eax
.L115:
	nop
	movq	camlA__const_block_183@GOTPCREL(%rip), %rdi
	movq	$1, %rbx
	movq	camlStdlib__printf__anon_fn$5bprintf$2eml$3a20$2c14$2d$2d48$5d_439_closure@GOTPCREL(%rip), %rax
	call	camlCamlinternalFormat__make_printf_4932@PLT
.L112:
	movq	%rax, %rbx
	movq	(%rbx), %rdi
	movq	(%rsp), %rax
	addq	$8, %rsp
	.cfi_adjust_cfa_offset -8
	jmp	*%rdi
	.cfi_adjust_cfa_offset 8
	.cfi_adjust_cfa_offset -8
	.cfi_endproc
	.type camlA__test2_118,@function
	.size camlA__test2_118,. - camlA__test2_118
	.text
	.align	16
	.globl	camlA__probe_handler_a_256
camlA__probe_handler_a_256:
	.cfi_startproc
	subq	$8, %rsp
	.cfi_adjust_cfa_offset 8
.L117:
	movq	%rbx, %rdi
	movq	%rdi, %r11
	imulq	$10, %r11
	addq	$-9, %r11
	movq	%rdi, %r10
	imulq	$9, %r10
	addq	$-8, %r10
	leaq	-7(,%rdi,8), %r13
	movq	%rdi, %r12
	imulq	$7, %r12
	addq	$-6, %r12
	movq	%rdi, %r9
	imulq	$6, %r9
	addq	$-5, %r9
	movq	%rdi, %r8
	imulq	$5, %r8
	addq	$-4, %r8
	leaq	-3(,%rdi,4), %rcx
	movq	%rdi, %rdx
	imulq	$3, %rdx
	addq	$-2, %rdx
	leaq	-1(%rdi,%rdi), %rsi
	xorq	%rbx, %rbx
	incq	%rbx
	movq	camlA__const_string_130@GOTPCREL(%rip), %rax
	subq	$16, %rsp
	.cfi_adjust_cfa_offset 16
	movq	%r10, (%rsp)
	movq	%r11, 8(%rsp)
	call	camlA__h2_14@PLT
.L116:
	addq	$16, %rsp
	.cfi_adjust_cfa_offset -16
	addq	$8, %rsp
	.cfi_adjust_cfa_offset -8
	ret
	.cfi_adjust_cfa_offset 8
	.cfi_adjust_cfa_offset -8
	.cfi_endproc
	.type camlA__probe_handler_a_256,@function
	.size camlA__probe_handler_a_256,. - camlA__probe_handler_a_256
	.data
	.align	8
	.quad	4864
	.globl	camlA
camlA:
	.quad	camlA__h2_14_closure
	.quad	camlA__h1_65_closure
	.quad	camlA__test1_86_closure
	.quad	camlA__test2_118_closure
	.data
	.align	8
	.data
	.align	8
	.data
	.align	8
	.data
	.align	8
	.data
	.align	8
	.data
	.align	8
	.data
	.align	8
	.quad	2827
	.globl	camlA__const_block_183
camlA__const_block_183:
	.quad	camlA__const_string_180
	.quad	camlA__const_block_72
	.data
	.align	8
	.quad	2044
	.globl	camlA__const_string_180
camlA__const_string_180:
	.ascii	"test "
	.space	2
	.byte	2
	.data
	.align	8
	.quad	2044
	.globl	camlA__const_string_130
camlA__const_string_130:
	.ascii	"test2"
	.space	2
	.byte	2
	.data
	.align	8
	.quad	2827
	.globl	camlA__const_block_107
camlA__const_block_107:
	.quad	camlA__const_string_104
	.quad	camlA__const_block_72
	.data
	.align	8
	.quad	2044
	.globl	camlA__const_string_104
camlA__const_string_104:
	.ascii	"test "
	.space	2
	.byte	2
	.data
	.align	8
	.quad	2044
	.globl	camlA__const_string_98
camlA__const_string_98:
	.ascii	"test1"
	.space	2
	.byte	2
	.data
	.align	8
	.quad	2827
	.globl	camlA__const_block_75
camlA__const_block_75:
	.quad	camlA__const_string_70
	.quad	camlA__const_block_74
	.data
	.align	8
	.quad	2818
	.globl	camlA__const_block_74
camlA__const_block_74:
	.quad	1
	.quad	camlA__const_block_73
	.data
	.align	8
	.quad	2828
	.globl	camlA__const_block_73
camlA__const_block_73:
	.quad	117
	.quad	camlA__const_block_72
	.data
	.align	8
	.quad	4868
	.globl	camlA__const_block_72
camlA__const_block_72:
	.quad	1
	.quad	1
	.quad	1
	.quad	camlA__const_block_71
	.data
	.align	8
	.quad	2828
	.globl	camlA__const_block_71
camlA__const_block_71:
	.quad	21
	.quad	1
	.data
	.align	8
	.quad	3068
	.globl	camlA__const_string_70
camlA__const_string_70:
	.ascii	"handler "
	.space	7
	.byte	7
	.data
	.align	8
	.quad	2827
	.globl	camlA__const_block_54
camlA__const_block_54:
	.quad	camlA__const_string_29
	.quad	camlA__const_block_53
	.data
	.align	8
	.quad	2818
	.globl	camlA__const_block_53
camlA__const_block_53:
	.quad	1
	.quad	camlA__const_block_52
	.data
	.align	8
	.quad	2828
	.globl	camlA__const_block_52
camlA__const_block_52:
	.quad	117
	.quad	camlA__const_block_51
	.data
	.align	8
	.quad	4868
	.globl	camlA__const_block_51
camlA__const_block_51:
	.quad	1
	.quad	1
	.quad	1
	.quad	camlA__const_block_50
	.data
	.align	8
	.quad	2828
	.globl	camlA__const_block_50
camlA__const_block_50:
	.quad	65
	.quad	camlA__const_block_49
	.data
	.align	8
	.quad	4868
	.globl	camlA__const_block_49
camlA__const_block_49:
	.quad	1
	.quad	1
	.quad	1
	.quad	camlA__const_block_48
	.data
	.align	8
	.quad	2828
	.globl	camlA__const_block_48
camlA__const_block_48:
	.quad	65
	.quad	camlA__const_block_47
	.data
	.align	8
	.quad	4868
	.globl	camlA__const_block_47
camlA__const_block_47:
	.quad	1
	.quad	1
	.quad	1
	.quad	camlA__const_block_46
	.data
	.align	8
	.quad	2828
	.globl	camlA__const_block_46
camlA__const_block_46:
	.quad	65
	.quad	camlA__const_block_45
	.data
	.align	8
	.quad	4868
	.globl	camlA__const_block_45
camlA__const_block_45:
	.quad	1
	.quad	1
	.quad	1
	.quad	camlA__const_block_44
	.data
	.align	8
	.quad	2828
	.globl	camlA__const_block_44
camlA__const_block_44:
	.quad	65
	.quad	camlA__const_block_43
	.data
	.align	8
	.quad	4868
	.globl	camlA__const_block_43
camlA__const_block_43:
	.quad	1
	.quad	1
	.quad	1
	.quad	camlA__const_block_42
	.data
	.align	8
	.quad	2828
	.globl	camlA__const_block_42
camlA__const_block_42:
	.quad	65
	.quad	camlA__const_block_41
	.data
	.align	8
	.quad	4868
	.globl	camlA__const_block_41
camlA__const_block_41:
	.quad	1
	.quad	1
	.quad	1
	.quad	camlA__const_block_40
	.data
	.align	8
	.quad	2828
	.globl	camlA__const_block_40
camlA__const_block_40:
	.quad	65
	.quad	camlA__const_block_39
	.data
	.align	8
	.quad	4868
	.globl	camlA__const_block_39
camlA__const_block_39:
	.quad	1
	.quad	1
	.quad	1
	.quad	camlA__const_block_38
	.data
	.align	8
	.quad	2828
	.globl	camlA__const_block_38
camlA__const_block_38:
	.quad	65
	.quad	camlA__const_block_37
	.data
	.align	8
	.quad	4868
	.globl	camlA__const_block_37
camlA__const_block_37:
	.quad	1
	.quad	1
	.quad	1
	.quad	camlA__const_block_36
	.data
	.align	8
	.quad	2828
	.globl	camlA__const_block_36
camlA__const_block_36:
	.quad	65
	.quad	camlA__const_block_35
	.data
	.align	8
	.quad	4868
	.globl	camlA__const_block_35
camlA__const_block_35:
	.quad	1
	.quad	1
	.quad	1
	.quad	camlA__const_block_34
	.data
	.align	8
	.quad	2828
	.globl	camlA__const_block_34
camlA__const_block_34:
	.quad	65
	.quad	camlA__const_block_33
	.data
	.align	8
	.quad	4868
	.globl	camlA__const_block_33
camlA__const_block_33:
	.quad	1
	.quad	1
	.quad	1
	.quad	camlA__const_block_32
	.data
	.align	8
	.quad	2828
	.globl	camlA__const_block_32
camlA__const_block_32:
	.quad	65
	.quad	camlA__const_block_72
	.data
	.align	8
	.quad	3068
	.globl	camlA__const_string_29
camlA__const_string_29:
	.ascii	"handler "
	.space	7
	.byte	7
	.text
	.align	16
	.globl	camlA__entry
camlA__entry:
	.cfi_startproc
	subq	$8, %rsp
	.cfi_adjust_cfa_offset 8
.L122:
.L121:
	movq	$51, %rax
	call	camlA__test1_86@PLT
.L118:
	movq	$3, %rax
	call	camlA__test2_118@PLT
.L119:
	jmp	.L121
.L120:
	movq	$1, %rax
	addq	$8, %rsp
	.cfi_adjust_cfa_offset -8
	ret
	.cfi_adjust_cfa_offset 8
	.cfi_adjust_cfa_offset -8
	.cfi_endproc
	.type camlA__entry,@function
	.size camlA__entry,. - camlA__entry
	.data
	.align	8
	.text
				/* probe a camlA__probe_handler_a_256 */
	.align	16
camlA__probe_wrapper_1:
	.cfi_startproc
	subq	$24, %rsp
	.cfi_adjust_cfa_offset 24
	movq	%rax, (%rsp)
	movq	%rbx, 8(%rsp)
	movq	8(%rsp), %rax
	movq	(%rsp), %rbx
	call	camlA__probe_handler_a_256@PLT
.L123:
	addq	$24, %rsp
	.cfi_adjust_cfa_offset -24
	ret
	.cfi_endproc
				/* probe a camlA__probe_handler_a_226 */
	.align	16
camlA__probe_wrapper_0:
	.cfi_startproc
	subq	$24, %rsp
	.cfi_adjust_cfa_offset 24
	movq	%rax, (%rsp)
	movq	%rbx, 8(%rsp)
	movq	8(%rsp), %rax
	movq	(%rsp), %rbx
	call	camlA__probe_handler_a_226@PLT
.L124:
	addq	$24, %rsp
	.cfi_adjust_cfa_offset -24
	ret
	.cfi_endproc
	.text
	.globl	camlA__code_end
camlA__code_end:
	.data
				/* relocation table start */
	.align	8
				/* relocation table end */
	.data
	.quad	0
	.globl	camlA__data_end
camlA__data_end:
	.quad	0
	.align	8
	.globl	camlA__frametable
camlA__frametable:
	.quad	12
	.quad	.L124
	.word	33
	.word	2
	.word	0
	.word	8
	.align	8
	.quad	.L125
	.quad	.L123
	.word	33
	.word	2
	.word	0
	.word	8
	.align	8
	.quad	.L126
	.quad	.L119
	.word	17
	.word	0
	.align	8
	.quad	.L127
	.quad	.L118
	.word	17
	.word	0
	.align	8
	.quad	.L128
	.quad	.L116
	.word	33
	.word	0
	.align	8
	.quad	.L129
	.quad	.L112
	.word	17
	.word	1
	.word	0
	.align	8
	.quad	.L130
	.quad	.L115
	.word	17
	.word	1
	.word	0
	.align	8
	.quad	.L126
	.quad	.L106
	.word	17
	.word	1
	.word	0
	.align	8
	.quad	.L134
	.quad	.L109
	.word	17
	.word	1
	.word	0
	.align	8
	.quad	.L125
	.quad	.L103
	.word	33
	.word	2
	.word	0
	.word	8
	.align	8
	.quad	.L138
	.quad	.L101
	.word	145
	.word	0
	.align	8
	.quad	.L142
	.quad	.L100
	.word	113
	.word	12
	.word	0
	.word	8
	.word	16
	.word	24
	.word	32
	.word	40
	.word	48
	.word	56
	.word	64
	.word	72
	.word	80
	.word	88
	.align	8
	.quad	.L143
	.align	8
.L144:
	.long	(.L146 - .) + -1409286144
	.long	106832
	.quad	.L145
	.align	8
.L135:
	.long	(.L146 - .) + -1409286144
	.long	106832
	.quad	.L136
	.align	8
.L129:
	.long	(.L147 - .) + -805306368
	.long	57441
	.quad	0
	.align	8
.L142:
	.long	(.L147 - .) + -1610612736
	.long	8225
	.quad	0
	.align	8
.L139:
	.long	(.L146 - .) + -1409286144
	.long	106832
	.quad	.L140
	.align	8
.L125:
	.long	(.L147 - .) + 1946157056
	.long	32800
	.quad	0
	.align	8
.L145:
	.long	(.L146 - .) + -1946157056
	.long	119056
	.quad	.L142
	.align	8
.L133:
	.long	(.L147 - .) + 1946157056
	.long	65568
	.quad	0
	.align	8
.L138:
	.long	(.L146 - .) + -67108864
	.long	81952
	.quad	.L139
	.align	8
.L140:
	.long	(.L146 - .) + -1946157056
	.long	119056
	.quad	.L141
	.align	8
.L134:
	.long	(.L146 - .) + -67108864
	.long	81952
	.quad	.L135
	.align	8
.L136:
	.long	(.L146 - .) + -1946157056
	.long	119056
	.quad	.L137
	.align	8
.L128:
	.long	(.L147 - .) + 805306368
	.long	81984
	.quad	0
	.align	8
.L137:
	.long	(.L147 - .) + 1946157056
	.long	36896
	.quad	0
	.align	8
.L132:
	.long	(.L146 - .) + -1946157056
	.long	119056
	.quad	.L133
	.align	8
.L143:
	.long	(.L146 - .) + -67108864
	.long	81952
	.quad	.L144
	.align	8
.L130:
	.long	(.L146 - .) + -67108864
	.long	81952
	.quad	.L131
	.align	8
.L131:
	.long	(.L146 - .) + -1409286144
	.long	106832
	.quad	.L132
	.align	8
.L141:
	.long	(.L147 - .) + -671088640
	.long	20736
	.quad	0
	.align	8
.L126:
	.long	(.L147 - .) + 469762048
	.long	49186
	.quad	0
	.align	8
.L127:
	.long	(.L147 - .) + 738197504
	.long	86080
	.quad	0
.L146:
	.ascii	"printf.ml\0"
	.align	8
.L147:
	.ascii	"a.ml\0"
	.align	8
	.section .note.stapsdt,"?","note"
	.align	4
	.long	.L149 - .L148
	.long	.L151 - .L150
	.long	3
.L148:
	.ascii	"stapsdt\0"
.L149:
	.align	4
.L150:
	.quad	.L115
	.quad	_.stapsdt.base
	.quad	camlA__semaphore_a
	.ascii	"ocaml\0"
	.ascii	"a\0"
	.ascii	"8@%rbx 8@%rax\0"
.L151:
	.align	4
	.align	4
	.long	.L153 - .L152
	.long	.L155 - .L154
	.long	3
.L152:
	.ascii	"stapsdt\0"
.L153:
	.align	4
.L154:
	.quad	.L109
	.quad	_.stapsdt.base
	.quad	camlA__semaphore_a
	.ascii	"ocaml\0"
	.ascii	"a\0"
	.ascii	"8@%rbx 8@%rax\0"
.L155:
	.align	4
	.section .stapsdt.base,"aG","progbits",.stapsdt.base,comdat
	.weak	_.stapsdt.base
	.hidden	_.stapsdt.base
_.stapsdt.base:
	.space	1
	.size _.stapsdt.base,1
	.section .probes,"wa","progbits"
	.align	2
	.globl	camlA__semaphore_a
camlA__semaphore_a:
	.word	0
	.section .note.GNU-stack,"",%progbits
