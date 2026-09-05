#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// ============================================================================
// Automatically Synthesized O(1) Loop Function Emitted by Strilight CodeGen
// ============================================================================
#include <stdint.h>

typedef struct {
    uint64_t acc;
} synthesized_loop_step_result_t;

synthesized_loop_step_result_t synthesized_loop_step(uint64_t N, uint64_t acc) {
    synthesized_loop_step_result_t res;
    res.acc = acc + ((N / 4) * 105);
    return res;
}

int check_key(int key) {
    if (key < 1000 || key > 9999) {
        printf("Key must be 4 digits!\n");
        return 0;
    }

    uint32_t k1 = (uint32_t)((key >> 8) & 0xFF);
    uint32_t k2 = (uint32_t)(key & 0xFF);

    uint32_t initial_acc = 0x1000;

    // Call the automatically synthesized O(1) closed-form C function!
    // Replaces the 1,000-iteration while loop in 1 nanosecond:
    synthesized_loop_step_result_t res = synthesized_loop_step(1000, initial_acc);
    uint32_t acc = res.acc;

    uint32_t final_check = (acc * k1) ^ (k2 * 0x1337);

    if (final_check == 0x6178D) {
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    int key = (argc > 1) ? atoi(argv[1]) : 1337;
    
    if (check_key(key)) {
        printf("ACCESS GRANTED\n");
        return 0;
    } else {
        printf("ACCESS DENIED\n");
        return 1;
    }
}
