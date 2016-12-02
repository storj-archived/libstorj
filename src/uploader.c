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
}

static void begin_upload_work(uv_work_t *work)
{
    int err;

    storj_upload_work_data_t *work_data = work->data;
    storj_env_t *env = &work_data->env;
    storj_upload_opts_t *opts = &work_data->opts;

    opts->file_name = strrchr(opts->file_path, '/');
    // Remove '/' from the front if exists by pushing the pointer up
    if (opts->file_name[0] == '/') opts->file_name++;

    opts->file_size = check_file(env, opts->file_path); // Expect to be up to 10tb
    if (opts->file_size < 1) {
        printf("Invalid file");
        return; //cleanup
    }

    opts->shard_size = determine_shard_size(&opts, NULL);
    opts->shard_num = ceil((double)opts->file_size / opts->shard_size);

    // Calculate deterministic file id
    char *file_id_buff = malloc(FILE_ID_SIZE);
    calculate_file_id(opts->bucket_id, opts->file_name, &file_id_buff);
    opts->file_id = file_id_buff;
    opts->file_id[FILE_ID_SIZE] = 0;


    // Encrypt file
    // struct aes256_ctx *ctx;
    // aes256_set_encrypt_key(ctx, const uint8_t *key);
    // aes256_encrypt(ctx, size_t length, uint8_t *dst, const uint8_t *src);

    // Load encrypted file
    FILE *fp;
    char buffer[4001];
    memset(buffer, '\0', 4001);
    fp = fopen(opts->file_path, "r");
    size_t bytesRead = 0;

    if (fp != NULL) {
      // read up to sizeof(buffer) bytes
      while ((bytesRead = fread(buffer, 1, 4000, fp)) > 0) {
        printf("buffer: %s\n", buffer);

        // TODO: Encrypt buffer and write to file
        memset(buffer, '\0', 4001);
      }
    }

    // TODO: upload file

    fclose(fp);
    free(file_id_buff);


}

int storj_bridge_store_file(storj_env_t *env, storj_upload_opts_t *opts)
{
    // TODO: Check options and env
    if (opts->file_concurrency < 1) {
        printf("\nFile Concurrency (%i) can't be less than 1", opts->file_concurrency);
        return -1;
    }

    if (opts->redundancy >= 12 || opts->redundancy < 0) {
        printf("\nRedundancy value (%i) is invalid", opts->redundancy);
        return -1;
    }

    uv_work_t *work = uv_work_new();

    storj_upload_work_data_t *work_data = malloc(sizeof(storj_upload_work_data_t));
    work_data->opts = *opts;
    work_data->env = *env;
    work->data = work_data;

    return uv_queue_work(env->loop, (uv_work_t*) work, begin_upload_work, uploader_callback);
}
