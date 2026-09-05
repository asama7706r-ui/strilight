#include <stdio.h>
#include "matrix_params.h"

/*
 * Example 2: In-Place Array Mutation with Developer Contract
 *
 * Demonstrates updating an array sequentially:
 * - target(buffer)             : The array memory slice being mutated in-place.
 * - include("matrix_params.h") : Statically defines ARRAY_SIZE and INITIAL_OFFSET.
 */
void update_buffer(int *buffer) {
    #pragma strilight accelerate target(buffer) include("matrix_params.h")
    for (int i = 0; i < ARRAY_SIZE; i++) {
        buffer[i] += INITIAL_OFFSET;
    }
}
