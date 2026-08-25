#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// crackme_pointers.c
// Array indexing, in-memory packed struct swapping, and indirect pointer resolution over 1,000 iterations.

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

    struct Element arr[1000];
    memset(arr, 0, sizeof(arr));

    // Fill the array using the key across 1,000 iterations
    for (int i = 0; i < 1000; i++) {
        arr[i].a = key ^ (i * 0x1111);
        arr[i].b = (short)(key + i * 0x22);
        arr[i].c = (char)(key + i * 0x3);
    }

    // Struct swap in stack memory
    struct Element temp = arr[1];
    arr[1] = arr[2];
    arr[2] = temp;

    // Indirect pointer resolution
    struct Element *p = &arr[key % 1000];
    
    // For key = 1337:
    // key % 1000 = 337
    // arr[1] has old arr[2]: key ^ (2 * 0x1111) = 1337 ^ 0x2222 = 0x271B (10011)
    // p = &arr[337]:
    // p->b = (short)(1337 + 337 * 0x22) = 12795
    // p->c = (char)(1337 + 337 * 0x3) = (char)(2348) = 44 (0x2C)
    // val = 10011 + (12795 * 16) + 44 = 214775 (0x346F7)
    int val = arr[1].a + (int)p->b * 0x10 + (int)p->c;

    if (val == 214775) {
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
