#include <stdio.h>
#include <stdlib.h>

// crackme_subregs.c
// Deep interleaved usage of 8-bit, 16-bit, 32-bit, and 64-bit writes on the same registers.
// Partial memory overlaps.

int check_key(int key) {
    if (key < 1000 || key > 9999) {
        printf("Key must be 4 digits!\n");
        return 0;
    }

    // Use a large constant to fill rax initially
    unsigned long long mixed_val = 0x1122334455667788ULL;

    __asm__ __volatile__(
        "mov rbx, %1 \n\t"
        "mov rax, %2 \n\t"
        "mov al, bl \n\t"
        "mov ah, bh \n\t"
        "shr ebx, 16 \n\t"
        "mov bx, 0 \n\t"
        "add ax, bx \n\t"
        "mov %0, rax \n\t"
        : "=r" (mixed_val)
        : "r" ((unsigned long long)key), "r" (mixed_val)
        : "rax", "rbx"
    );

    unsigned char buffer[16] = {0};
    unsigned int *dw_ptr = (unsigned int *)buffer;
    *dw_ptr = (unsigned int)(mixed_val & 0xFFFFFFFF);

    unsigned short *w_ptr = (unsigned short *)(buffer + 1);
    *w_ptr = (unsigned short)((mixed_val >> 32) & 0xFFFF);

    if (*dw_ptr == 0x55334439) {
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
