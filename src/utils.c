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

char *read_encrypted_file(char *filename, char *key)
{
  FILE *fp;
  fp = fopen(filename, "r");

  if (fp != NULL) {
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *result = malloc(fsize + 1);
    fread(result, fsize, 1, fp);

    if (ferror(fp)) {
      return NULL;
    }
    fclose(fp);

    if (key != NULL) {
      // Convert key to password
      uint8_t *pass = calloc(SHA256_DIGEST_SIZE + 1, sizeof(char));
      sha256_of_str(key, DETERMINISTIC_KEY_SIZE, pass);
      pass[SHA256_DIGEST_SIZE] = '\0';

      // Convert user email to salt
      // uint8_t *salt = calloc(RIPEMD160_DIGEST_SIZE + 1, sizeof(char));
      // ripemd160_of_str("user@example.com", sizeof("user@example.com"), salt);
      // salt[RIPEMD160_DIGEST_SIZE] = '\0';

      // Decrypt data
      struct aes256_ctx *ctx = calloc(sizeof(struct aes256_ctx), sizeof(char));
      aes256_set_decrypt_key(ctx, pass);
      // We only need the first 16 bytes of the salt because it's CTR mode
      // char *iv = calloc(AES_BLOCK_SIZE, sizeof(char));
      // memcpy(iv, salt, AES_BLOCK_SIZE);

      aes256_decrypt(ctx, AES_BLOCK_SIZE * 10, result, result);

      free(ctx);
      // free(iv);
      // free(salt);
      free(pass);

      return result;
    }

    result[fsize] = '\0';
    return result;
  }

  return NULL;
};

void write_encrypted_file(char *filename, char *key, char *data)
{
  FILE *fp;
  fp = fopen(filename, "w");

  if (fp != NULL) {
    if (key != NULL) {
      // Convert key to password
      uint8_t *pass = calloc(SHA256_DIGEST_SIZE + 1, sizeof(char));
      sha256_of_str(key, DETERMINISTIC_KEY_SIZE, pass);
      pass[SHA256_DIGEST_SIZE] = '\0';

      // Convert user email to salt
      // uint8_t *salt = calloc(RIPEMD160_DIGEST_SIZE + 1, sizeof(char));
      // ripemd160_of_str("user@example.com", sizeof("user@example.com"), salt);
      // salt[RIPEMD160_DIGEST_SIZE] = '\0';

      // Encrypt data
      struct aes256_ctx *ctx = calloc(sizeof(struct aes256_ctx), sizeof(char));
      aes256_set_encrypt_key(ctx, pass);
      // We only need the first 16 bytes of the salt because it's CTR mode
      // char *iv = calloc(AES_BLOCK_SIZE, sizeof(char));
      // memcpy(iv, salt, AES_BLOCK_SIZE);

      char *result = malloc(AES_BLOCK_SIZE * 10);
      aes256_encrypt(ctx, AES_BLOCK_SIZE * 10, result, data);

      fputs(result, fp);
      fclose(fp);

      free(ctx);
      // free(iv);
      // free(salt);
      free(pass);
      free(result);
      return;
    }

    fputs(data, fp);
    fclose(fp);
  }
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
