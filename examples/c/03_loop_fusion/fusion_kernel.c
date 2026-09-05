#include <stdio.h>

/*
 * Example 3: Loop Fusion Contract
 *
 * Demonstrates fusing two back-to-back loops targeting the same array.
 * Strilight combines them into a single loop / closed form kernel.
 */
void process_stream(int *stream, int count) {
    #pragma strilight fuse target(stream)
    for (int i = 0; i < count; i++) {
        stream[i] += 10;
    }
    for (int i = 0; i < count; i++) {
        stream[i] += 25;
    }
}
