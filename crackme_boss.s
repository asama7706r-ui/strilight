	.file	"crackme_boss.c"
	.intel_syntax noprefix
	.text
	.section .rdata,"dr"
.LC0:
	.ascii "Key too small!\0"
.LC1:
	.ascii "Key must be odd!\0"
	.text
	.globl	"check_key"
	.def	"check_key";	.scl	2;	.type	32;	.endef
	.seh_proc	"check_key"
"check_key":
	push	rbp
	.seh_pushreg	rbp
	mov	rbp, rsp
	.seh_setframe	rbp, 0
	sub	rsp, 80
	.seh_stackalloc	80
	.seh_endprologue
	mov	DWORD PTR 16[rbp], ecx
	cmp	DWORD PTR 16[rbp], 4999
	jg	.L2
	lea	rax, .LC0[rip]
	mov	rcx, rax
	call	"puts"
	mov	eax, 0
	jmp	.L6
.L2:
	mov	eax, DWORD PTR 16[rbp]
	and	eax, 1
	test	eax, eax
	jne	.L4
	lea	rax, .LC1[rip]
	mov	rcx, rax
	call	"puts"
	mov	eax, 0
	jmp	.L6
.L4:
	mov	eax, DWORD PTR 16[rbp]
	xor	eax, 85
	mov	edx, eax
	mov	eax, edx
	add	eax, eax
	add	eax, edx
	mov	DWORD PTR -4[rbp], eax
	mov	QWORD PTR -48[rbp], 0
	mov	QWORD PTR -40[rbp], 0
	lea	rax, -48[rbp]
	mov	QWORD PTR -16[rbp], rax
	mov	rax, QWORD PTR -16[rbp]
	mov	DWORD PTR [rax], -559038737
	lea	rax, -48[rbp]
	add	rax, 1
	mov	QWORD PTR -24[rbp], rax
	mov	eax, DWORD PTR -4[rbp]
	mov	edx, eax
	mov	rax, QWORD PTR -24[rbp]
	mov	WORD PTR [rax], dx
	mov	rax, QWORD PTR -16[rbp]
	mov	eax, DWORD PTR [rax]
	cmp	eax, -568889105
	jne	.L5
	mov	eax, 1
	jmp	.L6
.L5:
	mov	eax, 0
.L6:
	add	rsp, 80
	pop	rbp
	ret
	.seh_endproc
	.section .rdata,"dr"
.LC2:
	.ascii "Usage: %s <key>\12\0"
	.align 8
.LC3:
	.ascii "ACCESS GRANTED - YOU DEFEATED THE BOSS!\0"
.LC4:
	.ascii "ACCESS DENIED\0"
	.text
	.globl	"main"
	.def	"main";	.scl	2;	.type	32;	.endef
	.seh_proc	"main"
"main":
	push	rbp
	.seh_pushreg	rbp
	mov	rbp, rsp
	.seh_setframe	rbp, 0
	sub	rsp, 48
	.seh_stackalloc	48
	.seh_endprologue
	mov	DWORD PTR 16[rbp], ecx
	mov	QWORD PTR 24[rbp], rdx
	call	"__main"
	cmp	DWORD PTR 16[rbp], 1
	jg	.L8
	mov	rax, QWORD PTR 24[rbp]
	mov	rax, QWORD PTR [rax]
	lea	rcx, .LC2[rip]
	mov	rdx, rax
	call	"printf"
	mov	eax, 1
	jmp	.L9
.L8:
	mov	rax, QWORD PTR 24[rbp]
	add	rax, 8
	mov	rax, QWORD PTR [rax]
	mov	rcx, rax
	call	"atoi"
	mov	DWORD PTR -4[rbp], eax
	mov	eax, DWORD PTR -4[rbp]
	mov	ecx, eax
	call	"check_key"
	test	eax, eax
	je	.L10
	lea	rax, .LC3[rip]
	mov	rcx, rax
	call	"puts"
	jmp	.L11
.L10:
	lea	rax, .LC4[rip]
	mov	rcx, rax
	call	"puts"
.L11:
	mov	eax, 0
.L9:
	add	rsp, 48
	pop	rbp
	ret
	.seh_endproc
	.def	"__main";	.scl	2;	.type	32;	.endef
	.ident	"GCC: (MinGW-W64 x86_64-ucrt-posix-seh, built by Brecht Sanders, r2) 16.1.0"
	.def	"puts";	.scl	2;	.type	32;	.endef
	.def	"printf";	.scl	2;	.type	32;	.endef
	.def	"atoi";	.scl	2;	.type	32;	.endef
