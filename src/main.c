#include <array.h>
#include <hex.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

void elliptic();

int main(int argc, char* argv[]) {
  if (argc < 2) return 1;
  const long len = strlen(argv[1]);
  char hash[SHA256_DIGEST_LENGTH];
  SHA256(argv[1], len, hash);

  char hasher[48] = {};
  hex_to_binary("302e0201010420", hasher);
  printf("%d\n", strlen(hasher));
  strcat(hasher, hash);
  char ddd[9] = {};
  hex_to_binary("a00706052b8104000a", ddd);
  // strcat(hasher, ddd);
  copy_array(&hasher[39], ddd, 9);
  print_hex(hasher, 48);
  exit(0);
  printf("%d\n", strlen(hasher));
  elliptic(hasher);
  return 0;
}

void elliptic(char* hasher) { printf("%s", hasher); }
