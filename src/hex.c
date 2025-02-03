#include <hex.h>

char hex_to_binary(char* hex_src, char* out) {
  uint8_t hex_len = strlen(hex_src);
  if (hex_len % 2 != 0) return 1;

  for (int i = 0; i < hex_len; i += 2) {
    uint8_t high, low;
    if (hex_char_to_binary(hex_src[i], &high) != 0 ||
        hex_char_to_binary(hex_src[i + 1], &low) != 0)
      return 1;
    ;
    out[i / 2] = (high << 4) | low;
  }
  return 0;
}

char hex_char_to_binary(char hex_char, uint8_t* out) {
  if (hex_char >= '0' && hex_char <= '9') {
    *out = hex_char - '0';
  } else if (hex_char >= 'a' && hex_char <= 'f') {
    *out = hex_char - 'a' + 10;
  } else {
    return 1;
  }
  return 0;
}

void print_hex(unsigned char* data, size_t length) {
  for (size_t i = 0; i < length; i++) {
    printf("%02x", data[i]);
  }
}
