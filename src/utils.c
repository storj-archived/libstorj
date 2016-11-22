#include "storj.h"

int hex2str(unsigned length, uint8_t *data, char *buffer)
{
    unsigned i;

    for (i = 0; i<length; i++) {
        sprintf(&buffer[i*2], "%02x ", data[i]);
    }

    return 0;
}

unsigned long long check_file(storj_env_t *env, char *filepath, void *callback)
{
    int r = 0;
    uv_fs_t *stat_req = malloc(sizeof(uv_fs_t));

    r = uv_fs_stat(env->loop, stat_req, filepath, callback);
    if (r < 0) {
        const char *msg = uv_strerror(r);
        printf("\nuv_fs_stat on %s: %s\n", filepath, msg);
        return 0;
    }

    long long size = (stat_req->statbuf.st_size);

    if (callback == NULL) {
        free(stat_req);
    }

    return size;
}

char *calculate_file_id(char *bucket, char *file_name)
{
    struct sha256_ctx ctx;

    // Combine bucket and file_name
    int name_len = strlen(bucket) + strlen(file_name);
    char name[name_len];
    strcpy(name, bucket);
    strcat(name, file_name);
    name[name_len] = '\0';

    uint8_t digest[SHA256_DIGEST_SIZE];

    sha256_init(&ctx);
    sha256_update(&ctx, name_len, name);
    sha256_digest(&ctx, SHA256_DIGEST_SIZE, digest);

    char buff[SHA256_DIGEST_SIZE*2+1];
    buff[SHA256_DIGEST_SIZE*2] = '\0';

    hex2str(SHA256_DIGEST_SIZE, digest, buff);

    return buff;
}
