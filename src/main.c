#include <base.h>
#include <hash.h>
#include <hex.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ripemd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <password>\n", argv[0]);
    return 1;
  }

  const char* password = argv[1];
  unsigned char password_hash[EVP_MAX_MD_SIZE];
  compute_sha256((const unsigned char*)password, strlen(password),
                 password_hash);

  // Create EC key from password hash
  EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
  if (!key) {
    fprintf(stderr, "Failed to create EC key\n");
    return 1;
  }

  BIGNUM* priv = BN_new();
  if (!priv) {
    fprintf(stderr, "Failed to create BIGNUM for private key\n");
    EC_KEY_free(key);
    return 1;
  }

  if (!BN_bin2bn(password_hash, EVP_MD_size(EVP_sha256()), priv)) {
    fprintf(stderr, "Failed to convert hash to BIGNUM\n");
    BN_free(priv);
    EC_KEY_free(key);
    return 1;
  }

  if (!EC_KEY_set_private_key(key, priv)) {
    fprintf(stderr, "Failed to set private key\n");
    BN_free(priv);
    EC_KEY_free(key);
    return 1;
  }

  // Get the generator point and group
  const EC_GROUP* group = EC_KEY_get0_group(key);
  const EC_POINT* generator = EC_GROUP_get0_generator(group);
  if (!group || !generator) {
    fprintf(stderr, "Failed to get generator point\n");
    BN_free(priv);
    EC_KEY_free(key);
    return 1;
  }

  // Create a new point for the public key
  EC_POINT* pub_point = EC_POINT_new(group);
  if (!pub_point) {
    fprintf(stderr, "Failed to create public key point\n");
    BN_free(priv);
    EC_KEY_free(key);
    return 1;
  }

  // Compute public key point = generator * private_key
  if (!EC_POINT_mul(group, pub_point, priv, NULL, NULL, NULL)) {
    fprintf(stderr, "Failed to compute public key point\n");
    EC_POINT_free(pub_point);
    BN_free(priv);
    EC_KEY_free(key);
    return 1;
  }

  // Set the computed public key
  if (!EC_KEY_set_public_key(key, pub_point)) {
    fprintf(stderr, "Failed to set public key\n");
    EC_POINT_free(pub_point);
    BN_free(priv);
    EC_KEY_free(key);
    return 1;
  }

  // Get public key
  const EC_POINT* pub = EC_KEY_get0_public_key(key);
  if (!pub) {
    fprintf(stderr, "Failed to get public key\n");
    EC_POINT_free(pub_point);
    BN_free(priv);
    EC_KEY_free(key);
    return 1;
  }

  BIGNUM* x = BN_new();
  BIGNUM* y = BN_new();
  if (!x || !y) {
    fprintf(stderr, "Failed to create BIGNUMs for coordinates\n");
    BN_free(x);
    BN_free(y);
    EC_POINT_free(pub_point);
    BN_free(priv);
    EC_KEY_free(key);
    return 1;
  }

  if (!EC_POINT_get_affine_coordinates_GFp(group, pub, x, y, NULL)) {
    fprintf(stderr, "Failed to get affine coordinates\n");
    BN_free(x);
    BN_free(y);
    EC_POINT_free(pub_point);
    BN_free(priv);
    EC_KEY_free(key);
    return 1;
  }

  // Convert private key to WIF format
  unsigned char priv_bytes[32];
  BN_bn2bin(priv, priv_bytes);

  // Add version byte (0x80) and checksum
  unsigned char wif_data[37];
  wif_data[0] = 0x80;
  memcpy(wif_data + 1, priv_bytes, 32);

  unsigned char hash1[EVP_MAX_MD_SIZE];
  unsigned char hash2[EVP_MAX_MD_SIZE];
  compute_sha256(wif_data, 33, hash1);
  compute_sha256(hash1, EVP_MD_size(EVP_sha256()), hash2);
  memcpy(wif_data + 33, hash2, 4);

  // Convert public key to wallet address format
  unsigned char pub_bytes[65];
  pub_bytes[0] = 0x04;
  BN_bn2bin(x, pub_bytes + 1);
  BN_bn2bin(y, pub_bytes + 33);

  unsigned char pub_hash1[EVP_MAX_MD_SIZE];
  unsigned char pub_hash2[EVP_MAX_MD_SIZE];
  unsigned char pub_hash3[RIPEMD160_DIGEST_LENGTH];

  compute_sha256(pub_bytes, 65, pub_hash1);
  RIPEMD160(pub_hash1, EVP_MD_size(EVP_sha256()), pub_hash3);

  unsigned char addr_data[25];
  addr_data[0] = 0x00;  // Version byte
  memcpy(addr_data + 1, pub_hash3, RIPEMD160_DIGEST_LENGTH);

  compute_sha256(addr_data, 21, pub_hash1);
  compute_sha256(pub_hash1, EVP_MD_size(EVP_sha256()), pub_hash2);
  memcpy(addr_data + 21, pub_hash2, 4);

  // Print results
  printf("\nBitcoin Wallet\n\n");
  printf("Password:\n%s\n\n", password);

  printf("Private Key:\n");
  for (int i = 0; i < 32; i++) {
    printf("%02x", priv_bytes[i]);
  }
  printf("\n\n");

  char* wif = base58_encode(wif_data, 37);
  if (!wif) {
    fprintf(stderr, "Failed to encode WIF\n");
    BN_free(x);
    BN_free(y);
    BN_free(priv);
    EC_KEY_free(key);
    return 1;
  }
  printf("Private Key, WIF:\n%s\n\n", wif);
  free(wif);

  printf("Public Key:\n");
  for (int i = 0; i < 65; i++) {
    printf("%02x", pub_bytes[i]);
  }
  printf("\n\n");

  char* addr = base58_encode(addr_data, 25);
  if (!addr) {
    fprintf(stderr, "Failed to encode address\n");
    BN_free(x);
    BN_free(y);
    BN_free(priv);
    EC_KEY_free(key);
    return 1;
  }
  printf("Public Key, Wallet:\n%s\n\n", addr);
  free(addr);

  // Cleanup
  EC_KEY_free(key);
  BN_free(priv);
  BN_free(x);
  BN_free(y);

  return 0;
}