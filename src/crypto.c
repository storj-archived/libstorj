#include "crypto.h"

void pbkdf2_hmac_sha512 (
    unsigned key_length,
    const uint8_t *key,
    unsigned iterations,
    unsigned salt_length, const uint8_t *salt,
    unsigned length, uint8_t *dst)
{
    struct hmac_sha512_ctx sha512ctx;

    hmac_sha512_set_key (&sha512ctx, key_length, key);
    PBKDF2 (&sha512ctx, hmac_sha512_update, hmac_sha512_digest,
    SHA512_DIGEST_SIZE, iterations, salt_length, salt, length, dst);
}

uint8_t *key_from_passphrase(const char *passphrase, const char *salt)
{
    uint8_t passphrase_len = strlen(passphrase);
    uint8_t salt_len = strlen(salt);
    uint8_t *key = calloc(SHA256_DIGEST_SIZE + 1, sizeof(uint8_t));
    if (!key) {
        return NULL;
    }
    int rounds = 200000;
    pbkdf2_hmac_sha256(passphrase_len, (uint8_t *)passphrase, rounds, salt_len,
                       (uint8_t *)salt, SHA256_DIGEST_SIZE, key);

    return key;
}

int decrypt_data(const char *passphrase, const char *salt, const char *data,
                 char **result)
{

    uint8_t *key = key_from_passphrase(passphrase, salt);
    if (!key) {
        return 1;
    }

    // Convert from hex string
    int len = strlen(data);
    if (len / 2 < GCM_DIGEST_SIZE + SHA256_DIGEST_SIZE + 1) {
        free(key);
        return 1;
    }
    int enc_len = len / 2;
    int data_size = enc_len - GCM_DIGEST_SIZE - SHA256_DIGEST_SIZE;
    uint8_t *enc = str2hex(len, (char *)data);
    if (!enc) {
        free(key);
        return 1;
    }

    // Get the expected digest and iv
    uint8_t digest[GCM_DIGEST_SIZE];
    uint8_t data_iv[SHA256_DIGEST_SIZE];
    uint8_t cipher_text[data_size];
    memcpy(&digest, enc, GCM_DIGEST_SIZE);
    memcpy(&data_iv, enc + GCM_DIGEST_SIZE, SHA256_DIGEST_SIZE);
    memcpy(&cipher_text, enc + GCM_DIGEST_SIZE + SHA256_DIGEST_SIZE, data_size);

    free(enc);

    struct gcm_aes256_ctx gcm_ctx;
    gcm_aes256_set_key(&gcm_ctx, key);
    gcm_aes256_set_iv(&gcm_ctx, SHA256_DIGEST_SIZE, data_iv);
    free(key);

    // Decrypt the data
    *result = calloc(data_size + 1, sizeof(char));
    int pos = 0;
    size_t remain = data_size;
    while (pos < data_size) {
        int len = AES_BLOCK_SIZE;
        if (remain < AES_BLOCK_SIZE) {
            len = remain;
        }
        gcm_aes256_decrypt(&gcm_ctx, len, (uint8_t *)*result + pos,
                           cipher_text + pos);
        pos += AES_BLOCK_SIZE;
        remain -= AES_BLOCK_SIZE;
    }

    uint8_t actual_digest[GCM_DIGEST_SIZE];
    gcm_aes256_digest(&gcm_ctx, GCM_DIGEST_SIZE, actual_digest);

    int digest_match = memcmp(actual_digest, digest, GCM_DIGEST_SIZE);
    if (digest_match != 0) {
        return 1;
    }

    return 0;
}

int encrypt_data(const char *passphrase, const char *salt, const char *data,
                 char **result)
{
    uint8_t *key = key_from_passphrase(passphrase, salt);
    if (!key) {
        return 1;
    }

    uint8_t data_size = strlen(data);
    if (data_size <= 0) {
        return 1;
    }

    // Generate synthetic iv with first half of sha512 hmac of data
    struct hmac_sha512_ctx hmac_ctx;
    hmac_sha512_set_key(&hmac_ctx, SHA256_DIGEST_SIZE, key);
    hmac_sha512_update(&hmac_ctx, data_size, (uint8_t *)data);
    uint8_t data_iv[SHA256_DIGEST_SIZE];
    hmac_sha512_digest(&hmac_ctx, SHA256_DIGEST_SIZE, data_iv);

    // Encrypt the data
    struct gcm_aes256_ctx gcm_ctx;
    gcm_aes256_set_key(&gcm_ctx, key);
    gcm_aes256_set_iv(&gcm_ctx, SHA256_DIGEST_SIZE, data_iv);
    free(key);

    int pos = 0;
    size_t remain = data_size;
    uint8_t cipher_text[data_size];
    while (pos < data_size) {
        int len = AES_BLOCK_SIZE;
        if (remain < AES_BLOCK_SIZE) {
            len = remain;
        }
        gcm_aes256_encrypt(&gcm_ctx, len, cipher_text + pos,
                           (uint8_t *)data + pos);
        pos += AES_BLOCK_SIZE;
        remain -= AES_BLOCK_SIZE;
    }

    // Get the digest
    uint8_t digest[GCM_DIGEST_SIZE];
    gcm_aes256_digest(&gcm_ctx, GCM_DIGEST_SIZE, digest);


    // Copy the digest, iv and cipher text to a buffer
    int buffer_size = GCM_DIGEST_SIZE + (SHA512_DIGEST_SIZE / 2) + data_size;
    uint8_t *buffer = calloc(buffer_size, sizeof(char));
    if (!buffer) {
        return 1;
    }
    memcpy(buffer, digest, GCM_DIGEST_SIZE);
    memcpy(buffer + GCM_DIGEST_SIZE, data_iv, SHA256_DIGEST_SIZE);
    memcpy(buffer + GCM_DIGEST_SIZE + SHA256_DIGEST_SIZE,
           &cipher_text, data_size);

    // Convert to hex string
    *result = hex2str(buffer_size, buffer);
    if (!*result) {
        return 1;
    }

    free(buffer);


    return 0;
}
