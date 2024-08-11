.extern main
.section .head.text
.global __export_start

__export_start:
    bl main
    mov x8, #139 // rt_sigreturn
    svc #0
    brk #0
