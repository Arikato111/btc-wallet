#include <array.h>

void copy_array(char* dest, char* src, size_t size) {
  for (int i = 0; i < size; i++) {
    dest[i] = src[i];
  }
}
