#include "utils.h"

// TODO possibly use ccan/str/hex/hex.c code for decode and encoding hex

int hex2str(unsigned length, uint8_t *data, char *buffer)
{
    unsigned i;

    memset(buffer, '\0', length*2 + 1);

    for (i = 0; i<length; i++) {
        sprintf(&buffer[i*2], "%02x ", data[i]);
    }

    return OK;
}

void print_int_array(uint8_t *array, unsigned length)
{
    printf("{");
    for (int i = 0; i < length; i++) {
        printf("%i", array[i]);
        if (i != length - 1) {
            printf(",");
        }
    }
    printf("}\n");
}

int str2hex(unsigned length, char *data, uint8_t *buffer)
{
    unsigned i;

    memset(buffer, '\0', length/2 + 1);

    unsigned int *tmp = calloc(length/2, sizeof(unsigned int));

    for (i = 0; i<(length/2); i++) {
        sscanf(data + (i*2), "%2x", tmp + i);
        buffer[i] = (uint8_t)tmp[i];
    }

    free(tmp);

    return OK;
}

void random_buffer(uint8_t *buf, size_t len)
{
    // TODO check os portability for randomness
    static FILE *frand = NULL;
#ifdef _WIN32
    srand((unsigned)time(NULL));
    size_t i;
    for (i = 0; i < len; i++) {
        buf[i] = rand() % 0xFF;
    }
#else
    if (!frand) {
        frand = fopen("/dev/urandom", "r");
    }
    size_t len_read = fread(buf, 1, len, frand);
    (void)len_read;
    assert(len_read == len);
#endif
}

uint64_t shard_size(int hops)
{
    return (8  * (1024 * 1024)) * pow(2, hops);
};

int *read_encrypted_file(char *filename, char *key, char *salt, char **result)
{
  FILE *fp;
  fp = fopen(filename, "r");
  if (fp == NULL) {
    return 1;
  }

  fseek(fp, 0, SEEK_END);
  uint8_t fsize = ftell(fp) + 1;
  fseek(fp, 0, SEEK_SET);

  *result = malloc(fsize);
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
    uint8_t keyLen = strlen(key);
    uint8_t saltLen = strlen(salt);
    uint8_t *pass = calloc(SHA256_DIGEST_SIZE + 1, sizeof(uint8_t));
    pbkdf2_hmac_sha256(keyLen, key, 1, saltLen, salt, SHA256_DIGEST_SIZE, pass);

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

  (*result)[fsize - 1] = '\0';
  return 0;
};
// TODO move to crypto

int write_encrypted_file(char *filename, char *key, char *salt, char *data)
{
  FILE *fp;
  fp = fopen(filename, "w");
  if (fp == NULL) {
    return 1;
  }

  if (key != NULL && salt != NULL) {
    // Convert key to password
    uint8_t keyLen = strlen(key);
    uint8_t saltLen = strlen(salt);
    uint8_t *pass = calloc(SHA256_DIGEST_SIZE + 1, sizeof(uint8_t));
    if (pass == NULL) {
      return 1;
    }
    pbkdf2_hmac_sha256(keyLen, key, 1, saltLen, salt, SHA256_DIGEST_SIZE, pass);

    // Encrypt data
    struct aes256_ctx *ctx = calloc(sizeof(struct aes256_ctx), sizeof(char));
    if (ctx == NULL) {
      return 1;
    }
    aes256_set_encrypt_key(ctx, pass);

    uint8_t dataSize = strlen(data) * sizeof(char) + 1;
    uint8_t rem = dataSize % AES_BLOCK_SIZE;
    uint8_t newSize = dataSize + (AES_BLOCK_SIZE - rem);
    char *dataToStore = malloc(newSize);
    if (dataToStore == NULL) {
      return 1;
    }
    memcpy(dataToStore, data, dataSize);

    char *result = malloc(newSize);
    if (result == NULL) {
      return 1;
    }
    aes256_encrypt(ctx, newSize, result, dataToStore);

    fwrite(result, newSize, 1, fp);
    fclose(fp);

    free(ctx);
    free(pass);
    free(result);
    free(dataToStore);
    return 0;
  }

  fputs(data, fp);
  fclose(fp);
  return 0;
};

uint64_t get_time_milliseconds() {
#ifdef _WIN32

    // Time between windows epoch and standard epoch
    const int64_t time_to_epoch = 116444736000000000LL;

    FILETIME ft;

    GetSystemTimePreciseAsFileTime(&ft);

    LARGE_INTEGER li;
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    li.QuadPart -= time_to_epoch;
    li.QuadPart /= 10000;

    uint64_t milliseconds = li.QuadPart;
#else
    struct timeval t;
    gettimeofday(&t, NULL);
    uint64_t milliseconds = t.tv_sec * 1000LL + t.tv_usec / 1000;
#endif

    return milliseconds;
}
