#ifndef INTEGRITY_H
#define INTEGRITY_H

#include "common.h"

/* CRC-32 Calculation */
uint32_t integrity_calculate_crc32(const uint8_t *data, size_t length);

/* SHA-256 Calculation */
typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t buffer[64];
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[32]);
void integrity_calculate_sha256(const uint8_t *data, size_t length, char out_hex[65]);

/* Comparison Helper */
bool integrity_verify_match(const char *hash_expected, const char *hash_actual);

#endif /* INTEGRITY_H */
