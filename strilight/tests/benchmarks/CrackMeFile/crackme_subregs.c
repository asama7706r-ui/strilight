#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// crackme_subregs.c
// Deep interleaved usage of 8-bit (AL, AH, BL, BH, CL, CH, DL, DH),
// 16-bit (AX, BX, CX, DX), 32-bit (EAX, EBX, ECX, EDX), and 64-bit (RAX, RBX, RCX, RDX)
// with overlapping byte-level memory writes.

int check_key(int key) {
    if (key < 1000 || key > 9999) {
        printf("Key must be 4 digits!\n");
        return 0;
    }

    uint64_t rax_val = 0x1122334455667788ULL;
    uint64_t rbx_val = (uint64_t)key;
    uint32_t cx_val = 0;
    uint32_t dl_val = 0;

    __asm__ __volatile__(
        "mov al, bl \n\t"              // al = key & 0xFF (0x39)
        "mov ah, bh \n\t"              // ah = (key >> 8) & 0xFF (0x05)
        "xor al, 0x5A \n\t"            // al = 0x39 ^ 0x5A = 0x63
        "add ah, 0x12 \n\t"            // ah = 0x05 + 0x12 = 0x17
        "mov cl, al \n\t"              // cl = 0x63
        "add cl, ah \n\t"              // cl = 0x63 + 0x17 = 0x7A
        "mov ch, 0xAA \n\t"            // ch = 0xAA -> cx = 0xAA7A
        "mov dl, bl \n\t"              // dl = 0x39
        "add dl, 1 \n\t"               // dl = 0x3A
        : "+a" (rax_val), "=c" (cx_val), "=d" (dl_val)
        : "b" (rbx_val)
    );

    uint8_t buffer[8] = {0};

    // 1. Write 32-bit EAX at buffer[0..3]
    uint32_t *dw_ptr = (uint32_t *)buffer;
    *dw_ptr = (uint32_t)(rax_val & 0xFFFFFFFF);

    // 2. Overlap write 16-bit CX at buffer[2..3]
    uint16_t *w_ptr = (uint16_t *)(buffer + 2);
    *w_ptr = (uint16_t)(cx_val & 0xFFFF);

    // 3. Overlap write 8-bit DL at buffer[1]
    buffer[1] = (uint8_t)(dl_val & 0xFF);

    // Read full 32-bit value at buffer[0]
    if (*dw_ptr == 0xAA7A3A63) {
        return 1;
    }

    return 0;
}

int get_input() {
    return 1337;
}

int main(int argc, char **argv) {
    int key = (argc > 1) ? atoi(argv[1]) : get_input();
    
    if (check_key(key)) {
        printf("ACCESS GRANTED\n");
        return 0;
    } else {
        printf("ACCESS DENIED\n");
        return 1;
    }
}
