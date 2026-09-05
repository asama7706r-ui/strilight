#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// crackme_license.c
// Multi-segment license key validation with active sign-extensions and mixed-width 64-bit arithmetic.

int check_key(int key) {
    if (key < 1000 || key > 9999) {
        printf("Key must be 4 digits!\n");
        return 0;
    }

    // Extract segments
    int8_t b3 = (int8_t)((key >> 8) & 0xFF);
    int8_t b4 = (int8_t)(key & 0xFF);

    // 1. Sign extensions (8 -> 16 -> 32 -> 64)
    int16_t s1 = (int16_t)b4;                       // cbw
    int32_t s2 = (int32_t)s1 * 0x33 + (int16_t)b3;  // cwde
    int64_t s3 = (int64_t)s2;                       // cdqe

    // 2. Negation and 64-bit sign-extension
    int32_t neg_part = -((int32_t)b3 * 0x111 + (int32_t)b4); // neg
    int64_t s4 = (int64_t)neg_part;                 // cdqe

    // 3. Combined 64-bit license equation
    int64_t final_license = (s3 * 0x1337) ^ s4;

    if (final_license == -14324782LL) {
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
