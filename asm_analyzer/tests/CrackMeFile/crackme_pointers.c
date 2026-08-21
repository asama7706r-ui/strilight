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
    struct Element temp = arr[1];
    arr[1] = arr[2];
    arr[2] = temp;

    // Indirect pointer resolution
    struct Element *p = &arr[key % 4];
    
    int val = arr[1].a + arr[1].b + arr[1].c;

    if (val == 0x2cd7) {
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
