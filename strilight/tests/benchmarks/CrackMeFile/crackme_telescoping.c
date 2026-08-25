#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// crackme_telescoping.c
// Validates Rule 5: The Telescoping Cascade for M Conditions
// Tests multi-branch switch-case and nested if-else condition lifting across 1,000 iterations.

int check_key(int key) {
    if (key < 1000 || key > 9999) {
        printf("Key must be 4 digits!\n");
        return 0;
    }

    uint32_t k1 = (uint32_t)((key >> 8) & 0xFF);
    uint32_t k2 = (uint32_t)(key & 0xFF);

    uint32_t acc = 0x1000;

    int i = 0;
    while (i < 1000) {
        uint32_t mode = (k1 + (i & 3)) & 3;
        if (mode == 0) {
            acc += 10;
        } else if (mode == 1) {
            // Nested condition depth 2
            if (k2 > 50) {
                acc += 25;
            } else {
                acc += 15;
            }
        } else if (mode == 2) {
            acc += 30;
        } else {
            // Fallback default branch
            acc += 40;
        }
        i++;
    }

    // For key = 1337 (0x0539):
    // k1 = 5, k2 = 57 (> 50)
    // 250 cycles * 105 = 26250 -> acc = 4096 + 26250 = 30346
    // final_check = (30346 * 5) ^ (57 * 4919) = 151730 ^ 280383 = 0x6178D (399245)
    uint32_t final_check = (acc * k1) ^ (k2 * 0x1337);

    if (final_check == 0x6178D) {
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
