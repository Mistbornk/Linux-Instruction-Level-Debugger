.section .text
.global _start, last_instruction
_start:
    mov $60, %eax
    xor %edi, %edi
    syscall
    .balign 4096
    .fill 4095,1,0x90
last_instruction:
    ret
.section .note.GNU-stack,"",@progbits
