#include <base.h>

// Base58 alphabet
const char* base58_alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Function to perform base58 encoding
char* base58_encode(const unsigned char* data, size_t len) {
  if (!data || len == 0) {
    return NULL;
  }

  BIGNUM* bn = BN_new();
  BIGNUM* dv = BN_new();
  BIGNUM* rem = BN_new();
  BN_CTX* ctx = BN_CTX_new();

  if (!bn || !dv || !rem || !ctx) {
    fprintf(stderr, "Failed to allocate BIGNUM resources\n");
    BN_free(bn);
    BN_free(dv);
    BN_free(rem);
    BN_CTX_free(ctx);
    return NULL;
  }

  if (!BN_bin2bn(data, len, bn)) {
    fprintf(stderr, "Failed to convert binary to BIGNUM\n");
    BN_free(bn);
    BN_free(dv);
    BN_free(rem);
    BN_CTX_free(ctx);
    return NULL;
  }

  char* result =
      malloc(len * 2);  // Base58 encoding can be up to 2x the input length
  if (!result) {
    fprintf(stderr, "Failed to allocate memory for result\n");
    BN_free(bn);
    BN_free(dv);
    BN_free(rem);
    BN_CTX_free(ctx);
    return NULL;
  }

  size_t result_len = 0;
  BIGNUM* base = BN_new();
  if (!base || !BN_set_word(base, 58)) {
    fprintf(stderr, "Failed to create base BIGNUM\n");
    free(result);
    BN_free(bn);
    BN_free(dv);
    BN_free(rem);
    BN_free(base);
    BN_CTX_free(ctx);
    return NULL;
  }

  while (!BN_is_zero(bn)) {
    if (!BN_div(dv, rem, bn, base, ctx)) {
      fprintf(stderr, "Failed to perform division\n");
      free(result);
      BN_free(bn);
      BN_free(dv);
      BN_free(rem);
      BN_free(base);
      BN_CTX_free(ctx);
      return NULL;
    }
    BN_copy(bn, dv);
    result[result_len++] = base58_alphabet[BN_get_word(rem)];
  }

  // Add leading zeros
  for (size_t i = 0; i < len && data[i] == 0; i++) {
    result[result_len++] = base58_alphabet[0];
  }

  // Reverse the string
  for (size_t i = 0; i < result_len / 2; i++) {
    char temp = result[i];
    result[i] = result[result_len - 1 - i];
    result[result_len - 1 - i] = temp;
  }
  result[result_len] = '\0';

  BN_free(bn);
  BN_free(dv);
  BN_free(rem);
  BN_free(base);
  BN_CTX_free(ctx);

  return result;
}
