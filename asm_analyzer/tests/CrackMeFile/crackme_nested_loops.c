#include <stdio.h>
#include <stdlib.h>

// crackme_nested_loops.c
// Outer loop + Inner loop where inner loop iterations and step deltas depend on full 16-bit symbolic user input.

unsigned int rol(unsigned int val, int r_bits) {
    int max_bits = 32;
    return (val << (r_bits % max_bits)) | (val >> (max_bits - (r_bits % max_bits)));
}

int check_key(int key) {
    if (key < 1000 || key > 9999) {
        printf("Key must be 4 digits!\n");
        return 0;
    }

    unsigned int v = 0xAA;
    for (int i = 0; i < 4; i++) {
        int delta = (key >> (i * 4)) & 0xF;
        for (int j = 0; j < delta; j++) {
            v = (v ^ 0x55) + 1;
            v = rol(v, 1);
        }
        v += i * 0x100;
    }

    if (v == 0x2642564) {
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
