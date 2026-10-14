.text
.global _start, boundary_site
_start:
    xor %edi, %edi
    mov $60, %eax
    syscall
    .fill 4095-(.-_start),1,0x90
boundary_site:
    ret
.section .note.GNU-stack,"",@progbits
