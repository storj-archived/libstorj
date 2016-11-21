#include "storj.h"

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
