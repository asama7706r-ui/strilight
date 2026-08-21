#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// crackme_license.c
// Multi-segment key validation with mixed sign-extensions (cdqe, movsxd, movzx, cwd, cdq).

int check_key(int key) {
    if (key < 1000 || key > 9999) {
        printf("Key must be 4 digits!\n");
        return 0;
    }

    // Treat the key as 4 bytes
    unsigned char b1 = (key >> 24) & 0xFF;
    unsigned char b2 = (key >> 16) & 0xFF;
    unsigned char b3 = (key >> 8) & 0xFF;
    unsigned char b4 = key & 0xFF;

    // Use sign extensions
    int16_t v1 = (int8_t)b4; 
    int32_t v2 = (int16_t)v1; 
    int64_t v3 = (int32_t)v2; 
    
    int neg_key = -key;

    int64_t magic = (int64_t)neg_key;
    int32_t p = (int32_t)magic; 
    int64_t q = p;

    if (q == -1337) {
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
