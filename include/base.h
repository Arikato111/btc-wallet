#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <stdio.h>

char* base58_encode(const unsigned char* data, size_t len);