#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// crackme_pointers.c
// Array indexing, in-memory struct packing, swapping, and indirect pointer resolution.

#pragma pack(push, 1)
struct Element {
    int a;
    short b;
    char c;
};
#pragma pack(pop)

int check_key(int key) {
    if (key < 1000 || key > 9999) {
        printf("Key must be 4 digits!\n");
        return 0;
    }

    struct Element arr[4];
    memset(arr, 0, sizeof(arr));

    // Fill the array using the key
    for (int i = 0; i < 4; i++) {
        arr[i].a = key ^ (i * 0x1111);
        arr[i].b = (short)(key + i * 0x22);
        arr[i].c = (char)(key + i * 0x3);
    }

    // Do some pointer arithmetic and swaps
    // Swap arr[1] and arr[2]
    struct Element temp = arr[1];
    arr[1] = arr[2];
    arr[2] = temp;

    // Indirect pointer resolution
    struct Element *p = &arr[key % 4];
    
    // We want to make sure the key resolves to a specific condition
    // For key = 1337, key % 4 = 1
    // arr[1] was originally arr[2], so arr[1].a = key ^ (2 * 0x1111) = 1337 ^ 0x2222 = 0x539 ^ 0x2222 = 0x271B
    
    // Let's create a simpler, more direct test for aliasing that Z3 can solve efficiently.
    // We will just do arr[1] modifications and read it back.
    
    int val = arr[1].a + arr[1].b + arr[1].c;
    // For key = 1337:
    // arr[1] was arr[2]
    // arr[2].a = 1337 ^ 0x2222 = 0x539 ^ 0x2222 = 0x271b (10011)
    // arr[2].b = 1337 + 0x44 = 1405
    // arr[2].c = (char)(1337 + 6) = (char)1343 = (char)63 (0x3F)
    // val = 10011 + 1405 + 63 = 11479 (0x2cd7)

    if (val == 0x2cd7) {
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
