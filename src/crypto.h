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
#include <nettle/ctr.h>

#include "bip39.h"
#include "utils.h"

#define FILE_ID_BY_NAME_SIZE 24
#define FILE_ID_SIZE 40
#define DETERMINISTIC_KEY_SIZE 64
#define DETERMINISTIC_KEY_HEX_SIZE 32

// TODO use *buffer for out instead of **buffer for many of these methods
// and figure out if we need null termination, and if so have this be set within
// the functions rather than needing to do this outside.

int sha256_of_str(const uint8_t *str, int str_len, uint8_t *digest);

int sha512_of_str(const uint8_t *str, int str_len, uint8_t *digest);

int ripemd160_of_str(const uint8_t *str, int str_len, uint8_t *digest);

int ripmd160sha256(uint8_t *data, uint64_t data_size, uint8_t **digest);

int ripmd160sha256_as_string(uint8_t *data, uint64_t data_size, char **digest);

int double_ripmd160sha256(uint8_t *data, uint64_t data_size, uint8_t **digest);

int double_ripmd160sha256_as_string(uint8_t *data, uint64_t data_size,
                                    char **digest);

void pbkdf2_hmac_sha512(unsigned key_length,
                        const uint8_t *key,
                        unsigned iterations,
                        unsigned salt_length, const uint8_t *salt,
                        unsigned length, uint8_t *dst);

/**
 * @brief Calculate file id by sha256ripemd160 of file data
 *
 * @param[in] fp Pointer to file data to be hashed
 * @param[in] salt Prepended to the file data data
 * @param[in] salt_len Length of the salt
 * @param[out] buffer 20 byte character array that is the file's id
 * @return A non-zero error value on failure and 0 on success.
 */
int calculate_file_id(FILE *fp, char *salt, int salt_len, char **digest);

/**
 * @brief Calculate file id by sha256ripemd160 ny file_name
 *
 * @param[in] bucket Character array of bucket id
 * @param[in] file_name Character array of file name
 * @param[out] buffer 12 byte character array that is the file's id
 * @return A non-zero error value on failure and 0 on success.
 */
int calculate_file_id_by_name(const char *bucket, const char *file_name, char **buffer);

/**
 * @brief Generate a bucket's key
 *
 * @param[in] Character array of the mnemonic
 * @param[in] bucket_id Character array of bucket id
 * @param[out] bucket_key 64 byte character array that is the bucket's key
 * @return A non-zero error value on failure and 0 on success.
 */
int generate_bucket_key(const char *mnemonic, const char *bucket_id,
                        char **bucket_key);

/**
 * @brief Generate a file's key
 *
 * @param[in] Character array of the mnemonic
 * @param[in] bucket_id Character array of bucket id
 * @param[in] file_id Character array of file id
 * @param[out] file_key 64 byte character array that is the bucket's key
 * @return A non-zero error value on failure and 0 on success.
 */
int generate_file_key(const char *mnemonic,
                      const char *bucket_id,
                      const char *file_id,
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
int get_deterministic_key(const char *key, int key_len,
                          const char *id, char **buffer);

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

/**
 * @brief Will derive an encryption key from passhrase
 *
 * Will use PBKDF2 to generate an encryption key from the passphrase.
 *
 * @param[in] passphrase - The passhrase
 * @param[in] salt - The salt used in the key derivation function
 * @return A key or NULL on failure.
 */
uint8_t *key_from_passphrase(const char *passphrase, const char *salt);

/**
 * @brief Will encrypt data with passphrase
 *
 * Data is encrypted using AES-256-CTR with a key generated from a key
 * derivation function with the passphrase.
 *
 * @param[in] passphrase - The passhrase used to encrypt the data
 * @param[in] salt - The salt used in the key derivation function
 * @param[in] data - The data to be encrypted
 * @param[out] result - The encrypted data encoded as hex string
 * @return A non-zero error value on failure and 0 on success.
 */
int encrypt_data(const char *passphrase,
                 const char *salt,
                 const char *data,
                 char **result);

/**
 * @brief Will decrypt data with passphrase
 *
 * Data is decrypted using AES-256-CTR with a key generated from a key
 * derivation function with the passphrase.
 *
 * @param[in] passphrase - The passhrase used to encrypt the data
 * @param[in] salt - The salt used in the key derivation function
 * @param[in] data - The hex string of encoded data
 * @param[out] result - The decrypted data
 */
int decrypt_data(const char *passphrase,
                 const char *salt,
                 const char *data,
                 char **result);

#endif /* STORJ_CRYPTO_H */
