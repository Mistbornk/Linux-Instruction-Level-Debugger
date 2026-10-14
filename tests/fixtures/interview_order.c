#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Both pointers are valid. The defect is choosing the wrong destination. */
_Alignas(8) volatile uint64_t invoice_total = 100;
_Alignas(8) volatile uint64_t shipping_fee = 0;

__attribute__((noinline)) void store_fee(volatile uint64_t* destination, uint64_t fee) {
    *destination = fee;
    /* Keep the post-store watchpoint RIP inside this established stack frame. */
    __asm__ volatile("nop" ::: "memory");
}

__attribute__((noinline)) void record_shipping(int fixed) {
    volatile uint64_t* destination = fixed ? &shipping_fee : &invoice_total;
    store_fee(destination, 7);
    __asm__ volatile("nop" ::: "memory");
}

__attribute__((noinline)) void process_order(int fixed) {
    record_shipping(fixed);
    __asm__ volatile("nop" ::: "memory");
}

int main(int argc, char** argv) {
    if (argc != 2 || (strcmp(argv[1], "bug") && strcmp(argv[1], "fixed"))) {
        fprintf(stderr, "usage: %s bug|fixed\n", argv[0]);
        return 2;
    }
    const int fixed = !strcmp(argv[1], "fixed");
    process_order(fixed);
    printf("INVOICE_TOTAL=%" PRIu64 " SHIPPING_FEE=%" PRIu64 "\n", invoice_total, shipping_fee);
    return invoice_total == 100 && shipping_fee == 7 ? 0 : 3;
}
