#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>

void compute_sha256(const unsigned char* input, size_t input_len,
                    unsigned char* output);
