/**
 * @file crypto.h
 * @brief Storj crypto utilities.
 *
 * Helper crypto utilities
 */
#ifndef STORJ_CRYPTO_H
#define STORJ_CRYPTO_H

#include <nettle/aes.h>
#include <nettle/ripemd160.h>
#include <nettle/hmac.h>
#include <nettle/pbkdf2.h>
#include <nettle/sha.h>

#include "bip39.h"
#include "utils.h"

#define FILE_ID_SIZE 24
#define DETERMINISTIC_KEY_SIZE 64

int sha256_of_str(const uint8_t *str, int str_len, uint8_t *digest);

int sha512_of_str(const uint8_t *str, int str_len, uint8_t *digest);

int ripemd160_of_str(const uint8_t *str, int str_len, uint8_t *digest);

void pbkdf2_hmac_sha512(unsigned key_length,
                        const uint8_t *key,
                        unsigned iterations,
                        unsigned salt_length, const uint8_t *salt,
                        unsigned length, uint8_t *dst);

/**
 * @brief Calculate file id by sha256ripemd160
 *
 * @param[in] bucket Character array of bucket id
 * @param[in] file_name Character array of file name
 * @param[out] buffer 12 byte character array that is the file's id
 * @return A non-zero error value on failure and 0 on success.
 */
int calculate_file_id(char *bucket, char *file_name, char **buffer);

/**
 * @brief Generate a bucket's key
 *
 * @param[in] Character array of the mnemonic
 * @param[in] bucket_id Character array of bucket id
 * @param[out] bucket_key 64 byte character array that is the bucket's key
 * @return A non-zero error value on failure and 0 on success.
 */
int generate_bucket_key(char *mnemonic, char *bucket_id, char **bucket_key);

/**
 * @brief Generate a file's key
 *
 * @param[in] Character array of the mnemonic
 * @param[in] bucket_id Character array of bucket id
 * @param[in] file_id Character array of file id
 * @param[out] file_key 64 byte character array that is the bucket's key
 * @return A non-zero error value on failure and 0 on success.
 */
int generate_file_key(char *mnemonic,
                      char *bucket_id,
                      char *file_id,
                      char **file_key);

/**
 * @brief Calculate deterministic key by getting sha512 of key + id
 *
 * @param[in] Character array of the key
 * @param[in] key_len Integer value of length of key
 * @param[in] id Character array id
 * @param[out] buffer 64 byte character array of the deterministic key
 * @return A non-zero error value on failure and 0 on success.
 */
int get_deterministic_key(char *key, int key_len, char *id, char **buffer);

/**
 * @brief Increment the iv for ctr decryption/encryption
 *
 * This function will modify iv and increment the counter based
 * on the bytes position and the AES block size, useful for decrypting
 * shards asynchronously.
 *
 * The iv must be 16 bytes, the AES block size, and the bytes_position
 * must a multiple of 16.
 *
 * @param[out] iv The ctr/iv to be incremented
 * @return A non-zero value on failure
 */
int increment_ctr_aes_iv(uint8_t *iv, uint64_t bytes_position);

#endif /* STORJ_CRYPTO_H */
