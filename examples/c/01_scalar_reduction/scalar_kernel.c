#include <stdio.h>
#include "config.h"

/*
 * Example 1: Scalar Accumulator Reduction with Developer Contract
 *
 * The developer contract explicitly specifies:
 * 1. target(total)        : The accumulator variable to reduce.
 * 2. include("config.h")  : The C header containing static bounds (N_STEPS, STEP_INC).
 * 3. model(linear)        : An affine linear recurrence model.
 */
long long compute_reduction(void) {
    long long total = 0;

    #pragma strilight accelerate target(total) include("config.h") model(linear)
    for (unsigned long long i = 0; i < N_STEPS; i++) {
        total += STEP_INC;
    }

    return total;
}

int main(void) {
    printf("Computing scalar reduction...\n");
    long long result = compute_reduction();
    printf("Result: %lld\n", result);
    return 0;
}
