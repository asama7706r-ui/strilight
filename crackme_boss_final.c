#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int check_key(int key) {
  if (key < 5000)
    return 0;
  if (key % 2 == 0)
    return 0;

  int magic = (key ^ 0x55) * 3;
  unsigned char buffer[16] = {0};

  unsigned int *dw_ptr = (unsigned int *)buffer;
  *dw_ptr = 0xDEADBEEF;

  unsigned short *w_ptr = (unsigned short *)(buffer + 1);
  *w_ptr = (unsigned short)magic;

  if (*dw_ptr == 0xDE1770EF) {
    return 1;
  }

  return 0;
}

int main(int argc, char **argv) {
  int key = 48116737;
  printf("Testing Key: %d\n", key);
  if (check_key(key)) {
    printf("ACCESS GRANTED - YOU DEFEATED THE BOSS!\n");
  } else {
    printf("ACCESS DENIED\n");
  }
  return 0;
}
