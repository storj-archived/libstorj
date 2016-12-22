/**
 * @file http.h
 * @brief Storj utilities.
 *
 * Helper utilities
 */
#ifndef STORJ_UTILS_H
#define STORJ_UTILS_H

int hex2str(unsigned length, uint8_t *data, char *buffer);

int str2hex(unsigned length, char *data, uint8_t *buffer);

int increment_ctr_aes_iv(uint8_t *iv, uint64_t bytes_position);

uint64_t check_file(storj_env_t *env, char *filepath);

void random_buffer(uint8_t *buf, size_t len);

#endif /* STORJ_UTILS_H */
