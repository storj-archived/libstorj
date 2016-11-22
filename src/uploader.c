#include "storj.h"

static uv_work_t *uv_work_new()
{
    uv_work_t *work = malloc(sizeof(uv_work_t));
    assert(work != NULL);
    return work;
}

void uploader_callback(uv_work_t *work, int status)
{
    storj_upload_work_data_t *work_data = work->data;
    storj_env_t *env = &work_data->env;
    storj_upload_opts_t *opts = &work_data->opts;

    printf("File name: %s\n", opts->file_name);
    printf("File size: %llu\n", opts->file_size);
    printf("Shard size: %llu\n", opts->shard_size);
    printf("Shard num: %i\n", opts->shard_num);
    printf("File ID: %s\n", opts->file_id);
}

static void begin_upload_work(uv_work_t *work)
{
    storj_upload_work_data_t *work_data = work->data;
    storj_env_t *env = &work_data->env;
    storj_upload_opts_t *opts = &work_data->opts;

    opts->file_name = strrchr(opts->file_path, '/');
    // Remove '/' from the front if exists by pushing the pointer up
    if (opts->file_name[0] == '/') opts->file_name++;

    opts->file_size = check_file(env, opts->file_path); // Expect to be up to 10tb
    opts->shard_size = determine_shard_size(&opts, NULL);
    opts->shard_num = ceil((double)opts->file_size / opts->shard_size);

    char *buff = malloc(SHA256_DIGEST_SIZE*2+1);
    calculate_file_id(opts->bucket_id, opts->file_name, &buff);

    opts->file_id = buff;

}

int storj_bridge_store_file(storj_env_t *env, storj_upload_opts_t *opts)
{
    uv_work_t *work = uv_work_new();

    storj_upload_work_data_t *work_data = malloc(sizeof(storj_upload_work_data_t));
    work_data->opts = *opts;
    work_data->env = *env;
    work->data = work_data;

    return uv_queue_work(env->loop, (uv_work_t*) work, begin_upload_work, uploader_callback);
}
