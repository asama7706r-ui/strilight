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
  if (key < 1000 || key >= 2000) {
    printf("Key out of range!\n");
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
  while (loop_counter < 2000) {
    // Nested loop trap to test our TraceCompressor's hierarchical folding!
    int inner_counter = 0;
    while (inner_counter < (key % 10)) {
      // We will now make `dummy` a weird changing sequence in each cycle.
      // inner_counter changes: 0, 1, 2, 3
      // dummy will be: 0x55, 0x54, 0x57, 0x56
      int dummy = (inner_counter % 2) ^ 0x55;

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

  // Check the final 32-bit value
  if (*dw_ptr == 0xDE42DAEF) {
    return 1;
  }

  return 0;
}

int get_input() { return 1729; }

int main(int argc, char **argv) {
  int key = 1729;

  if (check_key(key)) {
    printf("ACCESS GRANTED - YOU DEFEATED THE BOSS!\n");
  } else {
    printf("ACCESS DENIED\n");
  }
  return 0;
}
