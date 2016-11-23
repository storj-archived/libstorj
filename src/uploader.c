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

void open_cb(uv_fs_t* open_req) {
  int err = 0;
  if (open_req->result < 0) {
      const char *msg = uv_strerror(open_req->result);
      printf("\nuv_fs_open callback: %s\n", msg);
  }

  storj_upload_work_data_t *work_data = open_req->data;
  storj_env_t *env = &work_data->env;
  storj_upload_opts_t *opts = &work_data->opts;

  /* 3. Create buffer and initialize it */
  char *buf = calloc(opts->file_size, sizeof(char));
  uv_buf_t iov = uv_buf_init(buf, opts->file_size);

  /* 4. Setup read request */
  uv_fs_t *read_req = malloc(sizeof(uv_fs_t));
  work_data->read_req = read_req;
  read_req->data = work_data;

  /* 5. Read from the file into the buffer */
  err = uv_fs_read(uv_default_loop(), read_req, open_req->result, &iov, 1, 0, NULL);
  if (err < 0) {
      const char *msg = uv_strerror(err);
      printf("\nuv_fs_read %s: %s\n", opts->file_name, msg);
  }

  printf("***************\n%s\n****************\n", read_req->bufsml->base);
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
    if (opts->file_size < 1) printf("Invalid file"); //cleanup

    opts->shard_size = determine_shard_size(&opts, NULL);
    opts->shard_num = ceil((double)opts->file_size / opts->shard_size);

    // Calculate deterministic file id
    char *file_id_buff = malloc(SHA256_DIGEST_SIZE*2+1);
    calculate_file_id(opts->bucket_id, opts->file_name, &file_id_buff);
    opts->file_id = file_id_buff;

    // Load file
    uv_fs_t *open_req = malloc(sizeof(uv_fs_t));
    work_data->open_req  = open_req;
    open_req->data = work_data;

    err = uv_fs_open(env->loop, open_req, opts->file_path, O_RDONLY, S_IRUSR, open_cb);
    if (err < 0) {
        const char *msg = uv_strerror(err);
        printf("\nuv_fs_open on %s: %s\n", opts->file_path, msg);
        free(open_req);
        exit(0);
    }



    // encrypt file

    // Shard file

    // upload file

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
