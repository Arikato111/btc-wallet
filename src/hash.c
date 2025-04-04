#include <hash.h>
// Function to compute SHA256 hash using EVP interface
void compute_sha256(const unsigned char* input, size_t input_len,
                    unsigned char* output) {
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    fprintf(stderr, "Failed to create EVP_MD_CTX\n");
    return;
  }

  unsigned int output_len;
  if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) ||
      !EVP_DigestUpdate(ctx, input, input_len) ||
      !EVP_DigestFinal_ex(ctx, output, &output_len)) {
    fprintf(stderr, "Failed to compute SHA256\n");
  }

  EVP_MD_CTX_free(ctx);
}
