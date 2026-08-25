#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// crackme_nested_loops.c
// Nested Loop Composition: Outer loop (1,000 iterations) + Inner loop (5 iterations per outer cycle)
// Evaluates 5,000 total iterations solved in O(1) time via closed-form composed induction.

int check_key(int key) {
    if (key < 1000 || key > 9999) {
        printf("Key must be 4 digits!\n");
        return 0;
    }

    uint32_t k1 = (uint32_t)((key >> 8) & 0xFF);
    uint32_t k2 = (uint32_t)(key & 0xFF);

    volatile uint32_t acc = 0x1000;

    // Outer loop runs 1,000 iterations
    for (int i = 0; i < 1000; i++) {
        // Inner loop runs 5 iterations
        for (int j = 0; j < 5; j++) {
            acc += k1 * 3 + j;
        }
        acc += k2 * 2;
    }

    // For key = 1337 (0x0539):
    // k1 = 5, k2 = 57
    // Inner delta = 5 * (5 * 3) + (0+1+2+3+4) = 75 + 10 = 85
    // Outer step = 85 + (57 * 2) = 85 + 114 = 199
    // Final acc = 4096 + (1000 * 199) = 4096 + 199000 = 203096 (0x31958)
    if (acc == 203096) {
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
