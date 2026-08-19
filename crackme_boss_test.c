#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Crackme Boss
// Designed to break naive Backward Slicing and Flat ITE Memory models

int check_key(int key) {
  // Trap 1: The Control Dependency Trap
  // The backward slicer doesn't track path constraints (Forward tracker is
  // disabled). So if the engine finds a 'key' that passes the math below, it
  // might be < 5000.
  if (key < 1000) {
    printf("Key too small!\n");
    return 0;
  }
  if (key % 2 == 0) {
    printf("Key must be odd!\n");
    return 0;
  }

  // Math operation to track
  int magic = (key ^ 0x55) * 3;

  // Trap 3: The Symbolic Loop Trap
  // Now the loop counter starts based on the user's input!
  // We use bitwise AND which is fully supported by the translator
  int loop_counter = key & 0x7FFF;
  while (loop_counter < 10000) {
    // Nested loop trap to test our TraceCompressor's hierarchical folding!
    int inner_counter = 0;
    while (inner_counter < 4) {
      // We will now make `dummy` a weird changing sequence in each cycle.
      // inner_counter changes: 0, 1, 2, 3
      // dummy will be: 0x55, 0x54, 0x57, 0x56
      int dummy = inner_counter ^ 0x55;

      magic += 1;
      magic += dummy; // Now magic's delta is NON-CONSTANT! (Non-linear series)

      inner_counter++;
    }
    loop_counter++;
  }

  // Trap 2: The Partial Overlap Trap
  // Write 4 bytes, write 2 bytes in the middle, read 4 bytes.
  // Engine checking `addr == write_addr` will fail.
  unsigned char buffer[16] = {0};

  // Write a 32-bit value to buffer
  unsigned int *dw_ptr = (unsigned int *)buffer;
  *dw_ptr = 0xDEADBEEF; // Little endian: EF BE AD DE

  // Overwrite the middle with our magic value (partial write!)
  unsigned short *w_ptr = (unsigned short *)(buffer + 1);
  *w_ptr = (unsigned short)magic;

  // If key = 1957 -> magic = 398268 (0x613BC).
  // buffer becomes: EF BC 13 DE (which is 0xDE13BCEF)

  // Check the final 32-bit value
  if (*dw_ptr == 0xDE13BCEF) {
    return 1;
  }

  return 0;
}

int get_input() {
  // Return a concrete value that will force the emulator to take the winning
  // path We will slice backward and stop here, leaving the return value
  // symbolic in Z3. 5001 passes key < 5000 (false) and key % 2 == 0 (false).
  return 5001;
}

int main(int argc, char **argv) {
  int key = 34789;

  if (check_key(key)) {
    printf("ACCESS GRANTED - YOU DEFEATED THE BOSS!\n");
  } else {
    printf("ACCESS DENIED\n");
  }
  return 0;
}
