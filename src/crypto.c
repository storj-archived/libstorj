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

    return OK;
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

    return OK;
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

    return OK;
}

int double_ripmd160sha256(uint8_t *data, uint64_t data_size, char **digest)
{
    char *first_ripemd160_digest = calloc(RIPEMD160_DIGEST_SIZE, sizeof(char));
    ripmd160sha256(data, data_size, &first_ripemd160_digest);

    char *second_ripemd160_digest = calloc(RIPEMD160_DIGEST_SIZE, sizeof(char));
    ripmd160sha256(first_ripemd160_digest, RIPEMD160_DIGEST_SIZE, &second_ripemd160_digest);

    //Copy the result into buffer
    memcpy(*digest, second_ripemd160_digest, RIPEMD160_DIGEST_SIZE);

    free(first_ripemd160_digest);
    free(second_ripemd160_digest);

    return OK;
}

int double_ripmd160sha256_as_string(uint8_t *data, uint64_t data_size, char **digest)
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

    return OK;
}

int generate_bucket_key(const char *mnemonic, char *bucket_id, char **bucket_key)
{
    char *seed = calloc(128 + 1, sizeof(char));
    mnemonic_to_seed(mnemonic, "", &seed);
    seed[128] = '\0';
    get_deterministic_key(seed, 128, bucket_id, bucket_key);
    free(seed);
    return OK;
}

int generate_file_key(const char *mnemonic, char *bucket_id, char *file_id, char **file_key)
{
    char *bucket_key = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
    generate_bucket_key(mnemonic, bucket_id, &bucket_key);
    bucket_key[DETERMINISTIC_KEY_SIZE] = '\0';
    get_deterministic_key(bucket_key, 64, file_id, file_key);
    free(bucket_key);
    return OK;
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
    uint8_t sha512input_as_hex[input_len/2 + 1];
    memset(sha512input_as_hex, '\0', input_len/2 + 1);
    str2hex(input_len, sha512input, sha512input_as_hex);

    // Sha512 of hexdata
    uint8_t sha512_digest[SHA512_DIGEST_SIZE];
    sha512_of_str(sha512input_as_hex, input_len/2, sha512_digest);

    // Convert Sha512 hex to character array
    char sha512_str[SHA512_DIGEST_SIZE*2+1];
    memset(sha512_str, '\0', RIPEMD160_DIGEST_SIZE*2+1);
    hex2str(SHA512_DIGEST_SIZE, sha512_digest, sha512_str);

    //First 64 bytes of sha512
    memcpy(*buffer, sha512_str, DETERMINISTIC_KEY_SIZE);

    free(sha512input);

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
  uint8_t fsize = ftell(fp) + 1; // TODO why does this have +1?
  fseek(fp, 0, SEEK_SET);

  *result = malloc(fsize); // TODO change this to calloc
  if (*result == NULL) {
    return 1;
  }
  fread(*result, fsize, 1, fp);

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
    struct aes256_ctx *ctx = calloc(sizeof(struct aes256_ctx), sizeof(char));
    if (ctx == NULL) {
      return 1;
    }
    aes256_set_decrypt_key(ctx, pass);

    aes256_decrypt(ctx, fsize - 1, *result, *result);

    free(ctx);
    free(pass);

    return 0;
  }

  (*result)[fsize - 1] = '\0'; // not necessary if calloc is used
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

    // Encrypt data
    struct aes256_ctx *ctx = calloc(sizeof(struct aes256_ctx), sizeof(char));
    if (ctx == NULL) {
      return 1;
    }
    aes256_set_encrypt_key(ctx, pass);

    uint8_t data_size = strlen(data) * sizeof(char) + 1;
    uint8_t rem = data_size % AES_BLOCK_SIZE;
    uint8_t new_size = data_size + (AES_BLOCK_SIZE - rem);
    char *data_to_store = malloc(new_size);
    if (data_to_store == NULL) {
      return 1;
    }
    memcpy(data_to_store, data, data_size);

    char *result = malloc(new_size);
    if (result == NULL) {
      return 1;
    }
    aes256_encrypt(ctx, new_size, result, data_to_store);

    fwrite(result, new_size, 1, fp);
    fclose(fp);

    free(ctx);
    free(pass);
    free(result);
    free(data_to_store);
    return 0;
  }

  fputs(data, fp);
  fclose(fp);
  return 0;
}
