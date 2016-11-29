#include "storj.h"

int hex2str(unsigned length, uint8_t *data, char *buffer)
{
    unsigned i;

    memset(buffer, '\0', length*2 + 1);

    for (i = 0; i<length; i++) {
        sprintf(&buffer[i*2], "%02x ", data[i]);
    }

    return 0;
}

unsigned long long check_file(storj_env_t *env, char *filepath)
{
    int r = 0;
    uv_fs_t *stat_req = malloc(sizeof(uv_fs_t));

    r = uv_fs_stat(env->loop, stat_req, filepath, NULL);
    if (r < 0) {
        const char *msg = uv_strerror(r);
        printf("\nuv_fs_stat on %s: %s\n", filepath, msg);
        return 0;
    }

    long long size = (stat_req->statbuf.st_size);

    free(stat_req);

    return size;
}

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

    // Convert ripemd160 hex to character array
    char sha256_str[SHA256_DIGEST_SIZE*2+1];
    sha256_str[SHA256_DIGEST_SIZE*2] = '\0';
    memset(sha256_str, '\0', SHA256_DIGEST_SIZE*2+1);
    hex2str(SHA256_DIGEST_SIZE, sha256_digest, sha256_str);

    // Get the ripemd160 of the sha256
    uint8_t ripemd160_digest[RIPEMD160_DIGEST_SIZE];
    ripemd160_of_str(sha256_str, SHA256_DIGEST_SIZE*2, ripemd160_digest);

    // Convert ripemd160 hex to character array
    char ripemd160_str[RIPEMD160_DIGEST_SIZE*2+1];
    ripemd160_str[RIPEMD160_DIGEST_SIZE*2] = '\0';
    memset(ripemd160_str, '\0', RIPEMD160_DIGEST_SIZE*2+1);
    hex2str(RIPEMD160_DIGEST_SIZE, ripemd160_digest, ripemd160_str);

    //Copy the result into buffer
    memcpy(*buffer, ripemd160_str, 12);

    return 0;
}

int generate_deterministic_key(char **mnemonic)
{

    return 0;
}

int sha256_of_str(uint8_t *str, int str_len, uint8_t *digest)
{
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, str_len, str);
    sha256_digest(&ctx, SHA256_DIGEST_SIZE, digest);

    return 0;
}

int ripemd160_of_str(uint8_t *str, int str_len, uint8_t *digest)
{
    struct ripemd160_ctx ctx;
    ripemd160_init(&ctx);
    ripemd160_update(&ctx, str_len, str);
    ripemd160_digest(&ctx, RIPEMD160_DIGEST_SIZE, digest);

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
