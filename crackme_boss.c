#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <key>\n", argv[0]);
        return 1;
    }

    int user_key = atoi(argv[1]);
    
    // 1. Data Flow (Math)
    int transformed = (user_key ^ 0x5A) * 3;
    
    // 2. Control Flow (Conditions)
    if (transformed < 1000) {
        printf("Fail 1! Number too small.\n");
        return 1;
    }

    // 3. Memory Aliasing (Pointers)
    int *heap_mem = (int*)malloc(sizeof(int));
    if (heap_mem == NULL) {
        return 1;
    }
    
    *heap_mem = transformed; // Write via symbolic pointer
    
    // Some dummy operations
    int dummy = transformed + 5;
    
    // Final check reading from memory
    if (*heap_mem == 3456) {
        printf("SUCCESS! You cracked it!\n");
        free(heap_mem);
        return 0;
    } else {
        printf("Fail 2! Try again.\n");
        free(heap_mem);
        return 1;
    }
}
