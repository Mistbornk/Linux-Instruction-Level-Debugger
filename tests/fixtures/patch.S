.text
.global _start, zero_site, patch_site, patch_exit
_start:
    lea scratch(%rip), %rax
    xor %ecx, %ecx
zero_site:
    .byte 0x00, 0x08 /* add %cl,(%rax): a valid instruction beginning in zero. */
    xor %edi, %edi
    mov $7, %eax
patch_site:
    nop /* Patching to 0x97 (xchg %eax,%edi) changes the exit status to 7. */
    mov $60, %eax
patch_exit:
    syscall
.data
scratch: .byte 5
.section .note.GNU-stack,"",@progbits
