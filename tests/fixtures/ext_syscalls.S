.global _start
.section .text
_start:
    mov $200, %r12d
again:
    mov $39, %eax
    syscall
    dec %r12d
    jnz again
    mov $60, %eax
    xor %edi, %edi
    syscall
.section .note.GNU-stack,"",@progbits
