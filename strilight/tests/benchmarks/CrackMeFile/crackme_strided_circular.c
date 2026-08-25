#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// crackme_strided_circular.c
// Stress-tests Strided Interval indexing (step 4 / step 8),
// 32-bit Modular Integer Wrap-Around Overflow, and Dual-Mask bitwise operations.

uint32_t table[16] = {
    0x0000, 0x1004, 0x2008, 0x300c,
    0x4010, 0x5014, 0x6018, 0x701c,
    0x8020, 0x9024, 0xa028, 0xb02c,
    0xc030, 0xd034, 0xe038, 0xf03c
};

int check_key(int key) {
    if (key < 1000 || key > 9999) {
        printf("Key must be 4 digits!\n");
        return 0;
    }

    uint32_t k1 = (uint32_t)((key >> 8) & 0xFF);
    uint32_t k2 = (uint32_t)(key & 0xFF);

    // 1. Accumulator starting near 32-bit wrap point (0xFFFFF000)
    uint32_t acc = 0xFFFFF000;

    // 2. Strided circular loop: 1,000 iterations across memory table with overflow
    for (int i = 0; i < 1000; i++) {
        uint32_t elem = table[(i * 2) & 0xF];
        acc = acc + (elem * k1) + (k2 << (i & 31));
    }

    // 3. Bitwise Dual-Mask XOR and multiplication
    acc = acc ^ 0x55AA55AA;
    acc = acc + (k1 * k2);

    // 4. Target Comparison (0x5D279287 = 1562874503)
    if (acc == 0x5D279287) {
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
