bits 64

section .text
extern payload_main

entry_syscall:
    jmp     setflag

entry_nonsyscall:

%if (entry_nonsyscall - entry_syscall) != 2
%error "guard is not 2B"
%endif

    push    qword [rel self]
    push    qword [rel magic]

    lea     rdi, [rel cookie]
    call    payload_main
    int3

setflag:
    mov     byte [rel flagv], 1
    jmp     entry_nonsyscall

global my_syscall:function
my_syscall:
	mov rax, rdi ; syscall number
	mov rdi, rsi
	mov rsi, rdx
	mov rdx, rcx
	mov r10, r8
	mov r8, r9
	mov r9, [rsp+8] ; arg6 on stack
	syscall
	ret

global my_dlopen:function
my_dlopen:
    jmp [rel dlopen]

section .data

magic dq 0x68637450616b6142

section .bss

self   resq 1
dlopen resq 1
flagv  resb 1
cookie resb 16
