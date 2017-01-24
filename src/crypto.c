#include "crypto.h"

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
    memset(ripemd160_str, '\0', RIPEMD160_DIGEST_SIZE*2+1);
    hex2str(RIPEMD160_DIGEST_SIZE, ripemd160_digest, ripemd160_str);

    //Copy the result into buffer
    memcpy(*buffer, ripemd160_str, FILE_ID_SIZE);

    return 0;
}

int ripmd160sha256_as_string(uint8_t *data, uint64_t data_size, char **digest)
{
    char *ripemd160_digest = calloc(RIPEMD160_DIGEST_SIZE, sizeof(char));
    ripmd160sha256(data, data_size, &ripemd160_digest);

    // Convert ripemd160 hex to character array
    char ripemd160_str[RIPEMD160_DIGEST_SIZE*2+1];
    memset(ripemd160_str, '\0', RIPEMD160_DIGEST_SIZE*2+1);
    hex2str(RIPEMD160_DIGEST_SIZE, ripemd160_digest, ripemd160_str);

    //Copy the result into buffer
    memcpy(*digest, ripemd160_str, RIPEMD160_DIGEST_SIZE * 2);

    free(ripemd160_digest);

    return 0;
}

int ripmd160sha256(uint8_t *data, uint64_t data_size, char **digest)
{
    // Get the sha256 of the data
    uint8_t sha256_digest[SHA256_DIGEST_SIZE];
    sha256_of_str(data, data_size, sha256_digest);

    // Get the ripemd160 of the sha256
    uint8_t ripemd160_digest[RIPEMD160_DIGEST_SIZE];
    ripemd160_of_str(sha256_digest, SHA256_DIGEST_SIZE, ripemd160_digest);

    //Copy the result into buffer
    memcpy(*digest, ripemd160_digest, RIPEMD160_DIGEST_SIZE);

    return 0;
}

int double_ripmd160sha256(uint8_t *data, uint64_t data_size, char **digest)
{
    char *first_ripemd160_digest = calloc(RIPEMD160_DIGEST_SIZE, sizeof(char));
    ripmd160sha256(data, data_size, &first_ripemd160_digest);

    char *second_ripemd160_digest = calloc(RIPEMD160_DIGEST_SIZE, sizeof(char));
    ripmd160sha256(first_ripemd160_digest, RIPEMD160_DIGEST_SIZE,
                   &second_ripemd160_digest);

    //Copy the result into buffer
    memcpy(*digest, second_ripemd160_digest, RIPEMD160_DIGEST_SIZE);

    free(first_ripemd160_digest);
    free(second_ripemd160_digest);

    return 0;
}

int double_ripmd160sha256_as_string(uint8_t *data, uint64_t data_size,
                                    char **digest)
{
    char *ripemd160_digest = calloc(RIPEMD160_DIGEST_SIZE, sizeof(char));
    double_ripmd160sha256(data, data_size, &ripemd160_digest);

    // Convert ripemd160 hex to character array
    char ripemd160_str[RIPEMD160_DIGEST_SIZE*2+1];
    memset(ripemd160_str, '\0', RIPEMD160_DIGEST_SIZE*2+1);
    hex2str(RIPEMD160_DIGEST_SIZE, ripemd160_digest, ripemd160_str);

    //Copy the result into buffer
    memcpy(*digest, ripemd160_str, RIPEMD160_DIGEST_SIZE * 2);

    free(ripemd160_digest);

    return 0;
}

int generate_bucket_key(const char *mnemonic, char *bucket_id,
                        char **bucket_key)
{
    char *seed = calloc(128 + 1, sizeof(char));
    mnemonic_to_seed(mnemonic, "", &seed);
    seed[128] = '\0';
    get_deterministic_key(seed, 128, bucket_id, bucket_key);

    memset_zero(seed, 128 + 1);
    free(seed);

    return 0;
}

int generate_file_key(const char *mnemonic, char *bucket_id, char *file_id,
                      char **file_key)
{
    char *bucket_key = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
    generate_bucket_key(mnemonic, bucket_id, &bucket_key);
    bucket_key[DETERMINISTIC_KEY_SIZE] = '\0';

    get_deterministic_key(bucket_key, 64, file_id, file_key);

    memset_zero(bucket_key, DETERMINISTIC_KEY_SIZE + 1);
    free(bucket_key);

    return 0;
}

int get_deterministic_key(char *key, int key_len, char *id, char **buffer)
{
    int input_len = key_len + strlen(id);
    char *sha512input = calloc(input_len + 1, sizeof(char));

    // Combine key and id
    memcpy(sha512input, key, key_len);
    memcpy(sha512input + key_len, id, strlen(id));
    sha512input[input_len] = '\0';

    // Convert input to hexdata
    uint8_t sha512input_as_hex[input_len / 2 + 1];
    memset(sha512input_as_hex, '\0', input_len / 2 + 1);
    str2hex(input_len, sha512input, sha512input_as_hex);

    // Sha512 of hexdata
    uint8_t sha512_digest[SHA512_DIGEST_SIZE];
    sha512_of_str(sha512input_as_hex, input_len / 2, sha512_digest);

    // Convert Sha512 hex to character array
    char sha512_str[SHA512_DIGEST_SIZE * 2 + 1];
    memset(sha512_str, '\0', RIPEMD160_DIGEST_SIZE * 2 + 1);
    hex2str(SHA512_DIGEST_SIZE, sha512_digest, sha512_str);

    //First 64 bytes of sha512
    memcpy(*buffer, sha512_str, DETERMINISTIC_KEY_SIZE);

    memset_zero(sha512_str, SHA512_DIGEST_SIZE * 2 + 1);
    memset_zero(sha512_digest, SHA512_DIGEST_SIZE);
    memset_zero(sha512input_as_hex, input_len / 2 + 1);
    memset_zero(sha512input, input_len + 1);

    free(sha512input);

    return 0;
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

int increment_ctr_aes_iv(uint8_t *iv, uint64_t bytes_position)
{
    if (bytes_position % AES_BLOCK_SIZE != 0) {
        return 1;
    }

    uint64_t times = bytes_position / AES_BLOCK_SIZE;

    while (times) {
        unsigned int i = AES_BLOCK_SIZE - 1;
        if (++(iv)[i] == 0) {
            while (i > 0 && ++(iv)[--i] == 0);
        }
        times--;
    }

    return 0;
}

int read_encrypted_file(char *filename, char *key, char *salt, char **result)
{
    FILE *fp;
    fp = fopen(filename, "r");
    if (fp == NULL) {
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    uint8_t fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *tmp = calloc(fsize, sizeof(char));
    if (tmp == NULL) {
        return 1;
    }
    fread(tmp, fsize, 1, fp);

    if (ferror(fp)) {
        return 1;
    }
    fclose(fp);

    if (key != NULL && salt != NULL) {
        // Convert key to password
        uint8_t key_len = strlen(key);
        uint8_t salt_len = strlen(salt);
        uint8_t *pass = calloc(SHA256_DIGEST_SIZE + 1, sizeof(uint8_t));
        pbkdf2_hmac_sha256(key_len, key, 1, salt_len, salt, SHA256_DIGEST_SIZE, pass);

        // Decrypt data
        uint8_t data_size =  fsize - SHA256_DIGEST_SIZE;
        uint8_t *hash_sha256 = calloc(SHA256_DIGEST_SIZE, sizeof(uint8_t));
        uint8_t *hash_sha256_dup = calloc(SHA256_DIGEST_SIZE, sizeof(uint8_t));
        memcpy(hash_sha256, tmp, SHA256_DIGEST_SIZE);
        memcpy(hash_sha256_dup, tmp, SHA256_DIGEST_SIZE);
        uint8_t *to_decrypt = calloc(data_size, sizeof(uint8_t));
        memcpy(to_decrypt, tmp + SHA256_DIGEST_SIZE, data_size);

        // Encrypt data
        *result = calloc(data_size, sizeof(uint8_t));
        struct aes256_ctx *ctx1 = malloc(sizeof(struct aes256_ctx));
        aes256_set_encrypt_key(ctx1, pass);
        ctr_crypt(ctx1, (nettle_cipher_func *)aes256_encrypt,
                  AES_BLOCK_SIZE, hash_sha256,
                  data_size, *result, to_decrypt);

        struct sha256_ctx_gen *ctx2 = malloc(sizeof(struct sha256_ctx));
        sha256_init(ctx2);
        sha256_update(ctx2, data_size, *result);
        uint8_t *hash_sha256_gen = calloc(SHA256_DIGEST_SIZE, sizeof(uint8_t));
        sha256_digest(ctx2, SHA256_DIGEST_SIZE, hash_sha256_gen);
        int sha_match = memcmp(hash_sha256_gen, hash_sha256_dup, SHA256_DIGEST_SIZE);
        if (sha_match != 0) {
            return 1;
        }

        free(ctx1);
        free(ctx2);
        free(pass);

        return 0;
    } else {
      *result = tmp;
    }

    return 0;
}

int write_encrypted_file(char *filename, char *key, char *salt, char *data)
{
    FILE *fp;
    fp = fopen(filename, "w");
    if (fp == NULL) {
        return 1;
    }

    if (key != NULL && salt != NULL) {
        // Convert key to password
        uint8_t key_len = strlen(key);
        uint8_t salt_len = strlen(salt);
        uint8_t *pass = calloc(SHA256_DIGEST_SIZE + 1, sizeof(uint8_t));
        if (pass == NULL) {
            return 1;
        }
        pbkdf2_hmac_sha256(key_len, key, 1, salt_len, salt, SHA256_DIGEST_SIZE, pass);

        uint8_t data_size = strlen(data);
        struct sha256_ctx *ctx1 = malloc(sizeof(struct sha256_ctx));
        sha256_init(ctx1);
        sha256_update(ctx1, data_size, data);
        uint8_t *hash_sha256 = calloc(SHA256_DIGEST_SIZE, sizeof(uint8_t));
        sha256_digest(ctx1, SHA256_DIGEST_SIZE, hash_sha256);
        fwrite(hash_sha256, SHA256_DIGEST_SIZE, 1, fp);

        // Encrypt data
        uint8_t *result = calloc(data_size, sizeof(uint8_t));
        struct aes256_ctx *ctx2 = malloc(sizeof(struct aes256_ctx));
        aes256_set_encrypt_key(ctx2, pass);
        ctr_crypt(ctx2, (nettle_cipher_func *)aes256_encrypt,
                  AES_BLOCK_SIZE, hash_sha256,
                  data_size, result, data);

        fwrite(result, data_size, 1, fp);
        fclose(fp);

        free(ctx1);
        free(ctx2);
        free(pass);
        free(result);
        return 0;
    }

    fputs(data, fp);
    fclose(fp);
    return 0;
}
