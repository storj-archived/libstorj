#include "utils.h"

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

    for (i = 0; i<(length/2); i++) {
        sscanf(data + (i*2), "%2x", buffer + i);
    }

    return OK;
}

void random_buffer(uint8_t *buf, size_t len)
{
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
