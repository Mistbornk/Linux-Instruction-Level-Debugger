.text
.global _start, exit_call
_start:
    xor %edi, %edi
    mov $60, %eax
exit_call:
    syscall
.section .note.GNU-stack,"",@progbits
