#ifndef ENC_H
#define ENC_H

#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t ENCRYPTION_KEY[32];

int get_key_for_passphrase(const char *passphrase, uint8_t *key);

int encrypt_bytes_with_passphrase(const char *input, size_t input_len,
                                  const uint8_t*key,
                                  uint8_t **output, size_t *output_len);

int decrypt_bytes_with_passphrase(const uint8_t *input, size_t input_len,
                                  const uint8_t *key,
                                  char **output, size_t *output_len);

#ifdef __cplusplus
}
#endif

#endif // ENC_H
