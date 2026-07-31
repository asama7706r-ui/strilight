#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Missing arguments\n");
        return 1;
    }
    
    int val = atoi(argv[1]);
    
    // The script looks for cmp with 3456
    if (val == 3456) {
        printf("Target matched!\n");
    } else {
        printf("Target not matched.\n");
    }
    
    return 0;
}
