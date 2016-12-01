#include "storj.h"

int calculate_file_id(char *bucket, char *file_name, char **buffer)
{
    // Combine bucket and file_name
    int name_len = strlen(bucket) + strlen(file_name);
    char name[name_len];
    strcpy(name, bucket);
    strcat(name, file_name);
    name[name_len] = '\0';

    // Get the sha256 of the file_name + bucket+id
    uint8_t sha256_digest[SHA256_DIGEST_SIZE];
    sha256_of_str(name, name_len, sha256_digest);

    // Get the ripemd160 of the sha256
    uint8_t ripemd160_digest[RIPEMD160_DIGEST_SIZE];
    ripemd160_of_str(sha256_digest, SHA256_DIGEST_SIZE, ripemd160_digest);

    // Convert ripemd160 hex to character array
    char ripemd160_str[RIPEMD160_DIGEST_SIZE*2+1];
    ripemd160_str[RIPEMD160_DIGEST_SIZE*2] = '\0';
    memset(ripemd160_str, '\0', RIPEMD160_DIGEST_SIZE*2+1);
    hex2str(RIPEMD160_DIGEST_SIZE, ripemd160_digest, ripemd160_str);

    //Copy the result into buffer
    memcpy(*buffer, ripemd160_str, 12);

    return OK;
}

int generate_bucket_key(char *mnemonic, char *bucketId, char **bucket_key)
{
    char *seed = calloc(128, sizeof(char));
    mnemonic_to_seed(mnemonic, "", &seed);
    get_deterministic_key(seed, bucketId, bucket_key);
    free(seed);
    return OK;
}

int get_deterministic_key(char *seed, char *id, char **buffer)
{
    int input_len = strlen(seed) + strlen(id);
    char *sha512input = calloc(input_len, sizeof(char));

    // Combine key and id
    memcpy(sha512input, seed, strlen(seed));
    memcpy(sha512input + strlen(seed), id, strlen(id));

    printf("sha512input: %s\n", sha512input);


    // Sha512 of key+id
    uint8_t sha512_digest[SHA512_DIGEST_SIZE];
    sha512_of_str(sha512input, input_len, sha512_digest);

    // Convert Sha512 hex to character array
    char sha512_str[SHA512_DIGEST_SIZE*2+1];
    sha512_str[SHA512_DIGEST_SIZE*2] = '\0';
    memset(sha512_str, '\0', SHA512_DIGEST_SIZE*2+1);
    hex2str(SHA512_DIGEST_SIZE, sha512_digest, sha512_str);

    //First 64 bytes of sha512
    memcpy(*buffer, sha512_str, 64);
    return OK;
}

int sha256_of_str(const uint8_t *str, int str_len, uint8_t *digest)
{
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, str_len, str);
    sha256_digest(&ctx, SHA256_DIGEST_SIZE, digest);

    return 0;
}

int ripemd160_of_str(const uint8_t *str, int str_len, uint8_t *digest)
{
    struct ripemd160_ctx ctx;
    ripemd160_init(&ctx);
    ripemd160_update(&ctx, str_len, str);
    ripemd160_digest(&ctx, RIPEMD160_DIGEST_SIZE, digest);

    return 0;
}

int sha512_of_str(const uint8_t *str, int str_len, uint8_t *digest)
{
    struct sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, str_len, str);
    sha512_digest(&ctx, SHA512_DIGEST_SIZE, digest);

    return 0;
}

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
