.text
.global _start, loop_body, after_loop, write_call, exit_call
_start:
    mov $10, %ecx
    xor %eax, %eax
loop_body:
    inc %eax
    dec %ecx
    jnz loop_body
after_loop:
    cmp $10, %eax
    jne failed
    mov $1, %eax
    mov $1, %edi
    lea message(%rip), %rsi
    mov $8, %edx
write_call:
    syscall
    xor %edi, %edi
    mov $60, %eax
exit_call:
    syscall
failed:
    mov $99, %edi
    mov $60, %eax
    syscall
.section .rodata
message: .ascii "LOOP=10\n"
.section .note.GNU-stack,"",@progbits
