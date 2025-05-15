#include "encryption.h"

#include "esp_random.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"

#define AES_BLOCK_SIZE 16

// PKCS#7 padding
static size_t pkcs7_pad(const uint8_t *input, size_t input_len, uint8_t **output) {
  size_t pad_len = AES_BLOCK_SIZE - (input_len % AES_BLOCK_SIZE);
  size_t out_len = input_len + pad_len;
  *output = malloc(out_len);
  memcpy(*output, input, input_len);
  memset(*output + input_len, pad_len, pad_len);
  return out_len;
}

// Remove PKCS#7 padding
static int pkcs7_unpad(uint8_t *buf, size_t buf_len, size_t *unpadded_len) {
  if (buf_len == 0) return -1;
  uint8_t pad_len = buf[buf_len - 1];
  if (pad_len == 0 || pad_len > AES_BLOCK_SIZE) return -1;
  // Check all padding bytes
  for (size_t i = 0; i < pad_len; ++i) {
    if (buf[buf_len - 1 - i] != pad_len) return -1;
  }
  *unpadded_len = buf_len - pad_len;
  return 0;
}

int get_key_for_passphrase(const char *passphrase, uint8_t *key) {
  // Derive key from passphrase using SHA-256
  mbedtls_sha256_context sha_ctx;
  mbedtls_sha256_init(&sha_ctx);
  mbedtls_sha256_starts(&sha_ctx, 0);
  mbedtls_sha256_update(&sha_ctx, (const unsigned char *)passphrase, strlen(passphrase));
  mbedtls_sha256_finish(&sha_ctx, key);
  mbedtls_sha256_free(&sha_ctx);
  return 0;
}

// Encrypts input of arbitrary length with passphrase, returns output buffer and sets output_len
// Output format: [16 bytes IV][ciphertext...]
int encrypt_bytes_with_passphrase(const char *input, size_t input_len,
                                  const uint8_t *key,
                                  uint8_t **output, size_t *output_len) {
  if (input_len == 0) {
    input_len = strlen((const char *)input) + 1;
  }

  uint8_t iv[AES_BLOCK_SIZE];

  // Generate random IV
  esp_fill_random(iv, AES_BLOCK_SIZE);

  // Pad input
  uint8_t *padded = NULL;
  size_t padded_len = pkcs7_pad((const uint8_t *)input, input_len, &padded);

  // Allocate output: IV + ciphertext
  *output_len = AES_BLOCK_SIZE + padded_len;
  *output = malloc(*output_len);
  memcpy(*output, iv, AES_BLOCK_SIZE);

  // AES-CBC encryption
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, key, 256);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv, padded, *output + AES_BLOCK_SIZE);
  mbedtls_aes_free(&aes);

  free(padded);
  return 0;
}

// Returns 0 on success, negative on error
int decrypt_bytes_with_passphrase(const uint8_t *input, size_t input_len,
                                  const uint8_t *key,
                                  char **output, size_t *output_len) {
  if (input_len < AES_BLOCK_SIZE || (input_len - AES_BLOCK_SIZE) % AES_BLOCK_SIZE != 0) {
    return -1;  // invalid input length
  }

  uint8_t iv[AES_BLOCK_SIZE];
  uint8_t *decrypted = NULL;

  *output = NULL;
  *output_len = 0;

  // Extract IV
  memcpy(iv, input, AES_BLOCK_SIZE);

  size_t ciphertext_len = input_len - AES_BLOCK_SIZE;
  const uint8_t *ciphertext = input + AES_BLOCK_SIZE;

  // Allocate buffer for decrypted data
  decrypted = malloc(ciphertext_len);
  if (!decrypted) {
    return -2;  // memory allocation failed
  }

  // AES-CBC decryption
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_dec(&aes, key, 256);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ciphertext_len, iv, ciphertext, decrypted);
  mbedtls_aes_free(&aes);

  // Remove PKCS#7 padding
  size_t unpadded_len = 0;
  if (pkcs7_unpad(decrypted, ciphertext_len, &unpadded_len) != 0) {
    // Padding error: wrong passphrase or corrupted data
    free(decrypted);
    return -3;
  }

  // Allocate output buffer for unpadded data
  *output = malloc(unpadded_len);
  if (!*output) {
    free(decrypted);
    return -2;  // memory allocation failed
  }
  memcpy(*output, decrypted, unpadded_len);
  *output_len = unpadded_len;

  free(decrypted);
  return 0;
}