#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

char hex_to_binary(char* hex_src, char* out);
char hex_char_to_binary(char hex_char, uint8_t* out);
void print_hex(unsigned char* data, size_t length);
