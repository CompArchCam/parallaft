.extern main
.section .head.text
.global __export_start

__export_start:
    call main
    mov $15, %rax // rt_sigreturn
    syscall
    int3
