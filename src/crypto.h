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
#include <nettle/gcm.h>
#include <nettle/base64.h>

#include <stdlib.h>
#include <string.h>

#include "utils.h"

void pbkdf2_hmac_sha512(unsigned key_length,
                        const uint8_t *key,
                        unsigned iterations,
                        unsigned salt_length, const uint8_t *salt,
                        unsigned length, uint8_t *dst);

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
