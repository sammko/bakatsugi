bits 64

section .text

entry_syscall:
    jmp     setflag

entry_nonsyscall:

%if (entry_nonsyscall - entry_syscall) != 2
%error "guard is not 2B"
%endif

    push    qword [rel self]
    push    qword [rel magic]

    lea     rdi, [rel path]
    mov     rsi, 1 ; RTLD_LAZY
    call    [rel dlopen]
    int3

setflag:
    mov     byte [rel flagv], 1
    jmp     entry_nonsyscall

section .data

magic dq 0x68637450616b6142

section .bss

self   resq 1
dlopen resq 1
flagv  resb 1
p_ref  resb 16
path   resb 256
