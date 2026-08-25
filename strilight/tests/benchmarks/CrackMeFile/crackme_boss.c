#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Crackme Boss
// Designed to break naive Backward Slicing and Flat ITE Memory models

int check_key(int key) {
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

  // Symbolic Loop Trap
  int loop_counter = key & 0x7FFF;
  while (loop_counter < 2000) {
    int inner_counter = 0;
    while (inner_counter < (key % 10)) {
      int dummy = (inner_counter % 2) ^ 0x55;
      magic += 1;
      magic += dummy;
      inner_counter++;
    }
    loop_counter++;
  }

  // Partial Overlap Trap
  unsigned char buffer[16] = {0};
  unsigned int *dw_ptr = (unsigned int *)buffer;
  *dw_ptr = 0xDEADBEEF;

  unsigned short *w_ptr = (unsigned short *)(buffer + 1);
  *w_ptr = (unsigned short)magic;

  // Check the final 32-bit value (Goal: 1729)
  if (*dw_ptr == 0xDE42DAEF) {
    return 1;
  }

  return 0;
}

int get_input() { return 1729; }

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
