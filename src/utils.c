#include "storj.h"

int hex2str(unsigned length, uint8_t *data, char *buffer)
{
    unsigned i;

    memset(buffer, '\0', length*2 + 1);

    for (i = 0; i<length; i++) {
        sprintf(&buffer[i*2], "%02x ", data[i]);
    }

    return OK;
}

int str2hex(unsigned length, char *data, uint8_t *buffer)
{
    unsigned i;

    memset(buffer, '\0', length/2 + 1);

    for (i = 0; i<length; i++) {
        sscanf(data + (i*2), "%2x", buffer + i);
    }

    return OK;
}


unsigned long long check_file(storj_env_t *env, char *filepath)
{
    int r = 0;
    uv_fs_t *stat_req = malloc(sizeof(uv_fs_t));

    r = uv_fs_stat(env->loop, stat_req, filepath, NULL);
    if (r < 0) {
        const char *msg = uv_strerror(r);
        printf("\nuv_fs_stat on %s: %s\n", filepath, msg);
        free(stat_req);
        return 0;
    }

    long long size = (stat_req->statbuf.st_size);

    free(stat_req);

    return size;
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
