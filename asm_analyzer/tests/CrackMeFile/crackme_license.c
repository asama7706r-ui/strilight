#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// crackme_license.c
// Multi-segment key validation with mixed sign-extensions (cdqe, movsxd, movzx, cwd, cdq).
// The key input here can be just a single 32-bit int to fit our test runner, 
// and we'll split it into multiple parts, or we can use the 32-bit int to seed multiple variables.
// Actually, our engine takes the initial key as a 32-bit int. Let's stick with that for simplicity,
// and perform sign-extension operations on it.

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
    // CWD, CDQ, CDQE in C:
    
    int16_t v1 = (int8_t)b4; 
    int32_t v2 = (int16_t)v1; 
    int64_t v3 = (int32_t)v2; 
    
    // For 1337 = 0x0539
    // b4 = 0x39. v1 = 0x39. v2 = 0x39. v3 = 0x39.
    // Let's use negative numbers to trigger the sign extension bits.
    // Wait, the key is 1000 to 9999.
    // Max value 9999 = 0x270F. So b4 can be 0x0F (positive).
    // Let's negate it to test sign extension.
    
    int neg_key = -key; // -1337 = 0xFFFFFAC7
    // b4 = 0xC7 (199). (int8_t)199 = -57.
    // v1 = -57 (0xFFC7)
    // v2 = -57 (0xFFFFFFC7)
    // v3 = -57 (0xFFFFFFFFFFFFFFC7)

    int64_t magic = (int64_t)neg_key; // 0xFFFFFFFFFFFFFAC7
    
    // Use some x86 instructions implicitly via C types
    int32_t p = (int32_t)magic; 
    int64_t q = p; // movsxd

    // Final check
    // For 1337, q = -1337 (0xFFFFFFFFFFFFFAC7).
    if (q == -1337) {
        return 1;
    }
    return 0;
}

int get_input() {
    return 1337;
}

int main(int argc, char **argv) {
    int key = get_input();
    
    if (check_key(key)) {
        printf("ACCESS GRANTED\n");
    } else {
        printf("ACCESS DENIED\n");
    }
    return 0;
}
