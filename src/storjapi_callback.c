#include "storjapi_callback.h"

//#define debug_enable

#define MAX_UPLOAD_FILES        256

static inline void noop() {};

static void get_input(char *line)
{
    if (fgets(line, BUFSIZ, stdin) == NULL) {
        line[0] = '\0';
    } else {
        int len = strlen(line);
        if (len > 0) {
            char *last = strrchr(line, '\n');
            if (last) {
                last[0] = '\0';
            }
            last = strrchr(line, '\r');
            if (last) {
                last[0] = '\0';
            }
        }
    }
}

/* inserts into subject[] at position pos */
void append(char subject[], const char insert[], int pos)
{
    char buf[256] = { }; 

    /* copy at most first pos characters */
    strncpy(buf, subject, pos); 
    int len = strlen(buf);

    /* copy all of insert[] at the end */
    strcpy(buf + len, insert); 

    /* increase the length by length of insert[] */
    len += strlen(insert);  

    /* copy the rest */
    strcpy(buf + len, subject + pos); 

    /* copy it back to subject */
    strcpy(subject, buf);  
}

char* replace_char(char* str, char find, char replace)
{
    char *current_pos = strchr(str, find);
    while (current_pos)
    {
        *current_pos = replace;
        append(current_pos, "_", 0);
        current_pos = strchr(current_pos, find);
    }
    return (str);
}

static void printdir(char *dir, int depth, FILE *src_fd, void *handle)
{
    DIR *dp;
    struct dirent *entry;
    struct stat statbuf;
    int spaces = depth*4;
    char tmp_dir[800] = {};
    char *full_path = NULL;
    char *s;
    char * start;
    storj_api_t *storj_api = handle;

    if((dp = opendir(dir)) == NULL)
    {
        fprintf(stderr,"cannot open directory: %s\n", dir);
        return;
    }

    chdir(dir);
    while((entry = readdir(dp)) != NULL)
    {
        lstat(entry->d_name, &statbuf);
        if (S_ISDIR(statbuf.st_mode))
        {
            /* Found a directory, but ignore . and .. */
            if (strcmp(".", entry->d_name) == 0 ||
                strcmp("..", entry->d_name) == 0) continue;

            /* Recurse at a new indent level */
            printdir(entry->d_name, depth + 1, src_fd, handle);
        } 
        else
        {
            full_path = realpath(entry->d_name, NULL);
            /* write to src file */
            fprintf(src_fd, "%s%s\n", "", full_path);
        }
    }
    chdir("..");
    closedir(dp);
    free(full_path);
}

static int file_exists(void *handle)
{
    struct stat sb;
    gid_t  st_grpid;
    storj_api_t *storj_api = handle;

    FILE *src_fd, *dst_fd;

    if (stat(storj_api->file_path, &sb) == -1)
    {
        perror("stat");
        return CLI_NO_SUCH_FILE_OR_DIR;
    }

    switch (sb.st_mode & S_IFMT)
    {
        case S_IFBLK:
            printf("block device\n");
            break;
        case S_IFCHR:
            printf("character device\n");
            break;
        case S_IFDIR:
            if((src_fd = fopen(storj_api->src_list, "w")) == NULL)
            {
                return CLI_UPLOAD_FILE_LOG_ERR;
            }
            printdir(storj_api->file_path, 0, src_fd, handle);
            fclose(src_fd);
            return CLI_VALID_DIR;
            break;
        case S_IFIFO:
            printf("FIFO/pipe\n");
            break;
        case S_IFLNK:
            printf("symlink\n");
            break;
        case S_IFREG:
            return CLI_VALID_REGULAR_FILE;
            break;
        case S_IFSOCK:
            printf("socket\n");
            break;
        default:
            printf("unknown?\n");
            break;
    }

    return CLI_UNKNOWN_FILE_ATTR;
}

static const char *get_filename_separator(const char *file_path)
{
    const char *file_name = NULL;
#ifdef _WIN32
    file_name = strrchr(file_path, '\\');
    if (!file_name) {
        file_name = strrchr(file_path, '/');
    }
    if (!file_name && file_path) {
        file_name = file_path;
    }
    if (!file_name) {
        return NULL;
    }
    if (file_name[0] == '\\' || file_name[0] == '/') {
        file_name++;
    }
#else
    file_name = strrchr(file_path, '/');
    if (!file_name && file_path) {
        file_name = file_path;
    }
    if (!file_name) {
        return NULL;
    }
    if (file_name[0] == '/') {
        file_name++;
    }
#endif
    return file_name;
}

static void close_signal(uv_handle_t *handle)
{
    ((void)0);
}

static void file_progress(double progress,
                          uint64_t downloaded_bytes,
                          uint64_t total_bytes,
                          void *handle)
{
    int bar_width = 70;

    if (progress == 0 && downloaded_bytes == 0) 
    {
        printf("Preparing File...");
        fflush(stdout);
        return;
    }

    printf("\r[");
    int pos = bar_width * progress;
    for (int i = 0; i < bar_width; ++i) 
    {
        if (i < pos) 
        {
            printf("=");
        } 
        else if (i == pos) 
        {
            printf(">");
        } 
        else 
        {
            printf(" ");
        }
    }
    printf("] %.*f%%", 2, progress * 100);

    fflush(stdout);
}

static void upload_file_complete(int status, storj_file_meta_t *file, void *handle)
{
    storj_api_t *storj_api = handle;
    storj_api->rcvd_cmd_resp = "upload-file-resp";

    printf("\n");
    if (status != 0) {
        printf("Upload failure: %s\n", storj_strerror(status));
        exit(status);
    }

    printf("Upload Success! File ID: %s\n", file->id);

    storj_free_uploaded_file_info(file);

    queue_next_cmd_req(storj_api);
}

static void upload_signal_handler(uv_signal_t *req, int signum)
{
    storj_upload_state_t *state = req->data;
    storj_bridge_store_file_cancel(state);
    if (uv_signal_stop(req)) {
        printf("Unable to stop signal\n");
    }
    uv_close((uv_handle_t *)req, close_signal);
}

static int upload_file(storj_env_t *env, char *bucket_id, const char *file_path, void *handle)
{
    storj_api_t *storj_api = handle;

    FILE *fd = fopen(file_path, "r");

    if (!fd) {
        printf("Invalid file path: %s\n", file_path);
        exit(0);
    }

    const char *file_name = get_filename_separator(file_path);

    if (storj_api->dst_file == NULL)
    {
        if (!file_name)
        {
            file_name = file_path;
        }
    }
    else
    {
        file_name = storj_api->dst_file;
    }

    // Upload opts env variables:
    char *prepare_frame_limit = getenv("STORJ_PREPARE_FRAME_LIMIT");
    char *push_frame_limit = getenv("STORJ_PUSH_FRAME_LIMIT");
    char *push_shard_limit = getenv("STORJ_PUSH_SHARD_LIMIT");
    char *rs = getenv("STORJ_REED_SOLOMON");

    storj_upload_opts_t upload_opts = {
        .prepare_frame_limit = (prepare_frame_limit) ? atoi(prepare_frame_limit) : 1,
        .push_frame_limit = (push_frame_limit) ? atoi(push_frame_limit) : 64,
        .push_shard_limit = (push_shard_limit) ? atoi(push_shard_limit) : 64,
        .rs = (!rs) ? true : (strcmp(rs, "false") == 0) ? false : true,
        .bucket_id = bucket_id,
        .file_name = file_name,
        .fd = fd
    };

    uv_signal_t *sig = malloc(sizeof(uv_signal_t));
    if (!sig) {
        return 1;
    }
    uv_signal_init(env->loop, sig);
    uv_signal_start(sig, upload_signal_handler, SIGINT);



    storj_progress_cb progress_cb = (storj_progress_cb)noop;
    if (env->log_options->level == 0) {
        progress_cb = file_progress;
    }

    storj_upload_state_t *state = storj_bridge_store_file(env,
                                                          &upload_opts,
                                                          handle,
                                                          progress_cb,
                                                          upload_file_complete);

    if (!state) {
        return 1;
    }

    sig->data = state;

    return state->error_status;
}

static void upload_files_complete(int status, storj_file_meta_t *file, void *handle)
{
    storj_api_t *storj_api = handle;
    storj_api->rcvd_cmd_resp = "upload-files-resp";

    printf("\n");
    if (status != 0) 
    {
        printf("[%s][%d]Upload failure: %s\n", 
               __FUNCTION__, __LINE__, storj_strerror(status));
    }
    else
    {
        printf("Upload Success! File ID: %s\n", file->id);
        storj_free_uploaded_file_info(file);
    }

    queue_next_cmd_req(storj_api);
}

static int upload_files(storj_env_t *env, char *bucket_id, const char *file_path, void *handle)
{
    storj_api_t *storj_api = handle;

    FILE *fd = fopen(file_path, "r");

    if (!fd) 
    {
        printf("[%s][%d]Invalid file : %s\n", __FUNCTION__, __LINE__, file_path);
        exit(0);
    }

    printf("Uploading[%d]of[%d] src file = %s as ",
           storj_api->xfer_count, storj_api->total_files, file_path);

    /* replace the dir with __ */
    char *s = strstr(storj_api->src_file, storj_api->file_path);
    char *start = s + strlen(storj_api->file_path);
    char tmp_dir[256];
    start = replace_char(start, '/', '_');
    memset(tmp_dir, 0x00, sizeof(tmp_dir));
    strcat(tmp_dir, storj_api->file_path);
    strcat(tmp_dir, start);
    storj_api->dst_file = tmp_dir;

    const char *file_name = get_filename_separator(storj_api->dst_file);

    if (!file_name) 
    {
        file_name = file_path;
    }
    printf(" %s\n", file_name);

    // Upload opts env variables:
    char *prepare_frame_limit = getenv("STORJ_PREPARE_FRAME_LIMIT");
    char *push_frame_limit = getenv("STORJ_PUSH_FRAME_LIMIT");
    char *push_shard_limit = getenv("STORJ_PUSH_SHARD_LIMIT");
    char *rs = getenv("STORJ_REED_SOLOMON");

    storj_upload_opts_t upload_opts = {
        .prepare_frame_limit = (prepare_frame_limit) ? atoi(prepare_frame_limit) : 1,
        .push_frame_limit = (push_frame_limit) ? atoi(push_frame_limit) : 64,
        .push_shard_limit = (push_shard_limit) ? atoi(push_shard_limit) : 64,
        .rs = (!rs) ? true : (strcmp(rs, "false") == 0) ? false : true,
        .bucket_id = bucket_id,
        .file_name = file_name,
        .fd = fd
    };

    uv_signal_t *sig = malloc(sizeof(uv_signal_t));
    if (!sig) {
        return 1;
    }
    uv_signal_init(env->loop, sig);
    uv_signal_start(sig, upload_signal_handler, SIGINT);

    storj_progress_cb progress_cb = (storj_progress_cb)noop;
    if (env->log_options->level == 0) {
        progress_cb = file_progress;
    }

    storj_upload_state_t *state = storj_bridge_store_file(env,
                                                          &upload_opts,
                                                          handle,
                                                          progress_cb,
                                                          upload_files_complete);

    if (!state) {
        return 1;
    }

    sig->data = state;

    return state->error_status;
}

static void verify_upload_files(void *handle)
{
    storj_api_t *storj_api = handle;
    int total_src_files = 0x00;
    int total_dst_files = 0x00;
    int ret = 0x00;

    /* upload list file previously not created? */
    if (storj_api->dst_file == NULL)
    {
        char pwd_path[256]= {};
        memset(pwd_path, 0x00, sizeof(pwd_path));
        char *upload_list_file = pwd_path;

        /* create upload files list based on the file path */
        if ((upload_list_file = getenv("TMPDIR")) != NULL)
        {
            if (upload_list_file[(strlen(upload_list_file) - 1)] == '/')
            {
                strcat(upload_list_file, "STORJ_output_list.txt");
            }
            else
            {
                strcat(upload_list_file, "/STORJ_output_list.txt");
            }

            /* check the directory and create the path to upload list file */
            memset(storj_api->src_list, 0x00, sizeof(storj_api->src_list));
            memcpy(storj_api->src_list, upload_list_file, sizeof(pwd_path));
            storj_api->dst_file = storj_api->src_list;
        }

        /* create a upload list file src_list.txt */
        int file_attr = file_exists(handle);
   }

    /* create a upload list file src_list.txt */
    storj_api->src_fd = fopen(storj_api->src_list, "r");

    if (!storj_api->src_fd)
    {
        printf("[%s][%d]Invalid file path: %s\n", 
                __FUNCTION__, __LINE__, storj_api->src_list);
        exit(0);
    } 
    else
    {
        /* count total src_list files */
        char line[MAX_UPLOAD_FILES][256];
        char *temp;
        int i = 0x00;

        memset(line, 0x00, sizeof(line));

        /* read a line from a file */
        while (fgets(line[i], sizeof(line), storj_api->src_fd) != NULL)
        {
            if (i <= MAX_UPLOAD_FILES)
            {
                i++;
            }
            else
            {
                i = (i - 1);
                printf("[%s][%d] Upload files limit set to %d \n", 
                       __FUNCTION__, __LINE__, (MAX_UPLOAD_FILES));
                break;
            }
        }

        total_src_files = i;
    }

    storj_api->total_files = total_src_files;
    storj_api->xfer_count = 0x01;

    storj_api->rcvd_cmd_resp = "verify-upload-files-resp";
    queue_next_cmd_req(storj_api);
}

static void download_file_complete(int status, FILE *fd, void *handle)
{
    storj_api_t *storj_api = handle;
    storj_api->rcvd_cmd_resp = "download-file-resp";

    printf("\n");
    fclose(fd);
    if (status) {
        // TODO send to stderr
        switch(status) {
            case STORJ_FILE_DECRYPTION_ERROR:
                printf("Unable to properly decrypt file, please check " \
                       "that the correct encryption key was " \
                       "imported correctly.\n\n");
                break;
            default:
                printf("[%s][%d]Download failure: %s\n",
                       __FUNCTION__, __LINE__, storj_strerror(status));
        }
    }
    else
    {
        printf("Download Success!\n");
    }

    queue_next_cmd_req(storj_api);
}

static void download_signal_handler(uv_signal_t *req, int signum)
{
    storj_download_state_t *state = req->data;
    storj_bridge_resolve_file_cancel(state);
    if (uv_signal_stop(req)) {
        printf("Unable to stop signal\n");
    }
    uv_close((uv_handle_t *)req, close_signal);
}

static int download_file(storj_env_t *env, char *bucket_id,
                         char *file_id, char *path, void *handle)
{
    FILE *fd = NULL;

    if (path) {
        char user_input[BUFSIZ];
        memset(user_input, '\0', BUFSIZ);

        if(access(path, F_OK) != -1 ) {
            printf("Warning: File already exists at path [%s].\n", path);
            while (strcmp(user_input, "y") != 0 && strcmp(user_input, "n") != 0)
            {
                memset(user_input, '\0', BUFSIZ);
                printf("Would you like to overwrite [%s]: [y/n] ", path);
                get_input(user_input);
            }

            if (strcmp(user_input, "n") == 0) {
                printf("\nCanceled overwriting of [%s].\n", path);
                return 1;
            }

            unlink(path);
        }

        fd = fopen(path, "w+");
    } else {
        fd = stdout;
    }

    if (fd == NULL) {
        // TODO send to stderr
        printf("Unable to open %s: %s\n", path, strerror(errno));
        return 1;
    }

    uv_signal_t *sig = malloc(sizeof(uv_signal_t));
    uv_signal_init(env->loop, sig);
    uv_signal_start(sig, download_signal_handler, SIGINT);

    storj_progress_cb progress_cb = (storj_progress_cb)noop;
    if (path && env->log_options->level == 0) {
        progress_cb = file_progress;
    }

    storj_download_state_t *state = storj_bridge_resolve_file(env, bucket_id,
                                                              file_id, fd, handle,
                                                              progress_cb,
                                                              download_file_complete);
    if (!state) {
        return 1;
    }
    sig->data = state;

    return state->error_status;
}

static void list_mirrors_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    storj_api_t *storj_api = req->handle;
    storj_api->last_cmd_req = storj_api->curr_cmd_req;
    storj_api->rcvd_cmd_resp = "list-mirrors-resp";

    if (req->status_code != 200) {
        printf("Request failed with status code: %i\n",
               req->status_code);
        goto cleanup;
    }

    if (req->response == NULL) {
        free(req);
        free(work_req);
        printf("Failed to list mirrors.\n");
        goto cleanup;
    }

    int num_mirrors = json_object_array_length(req->response);

    struct json_object *shard;
    struct json_object *established;
    struct json_object *available;
    struct json_object *item;
    struct json_object *hash;
    struct json_object *contract;
    struct json_object *address;
    struct json_object *port;
    struct json_object *node_id;

    for (int i = 0; i < num_mirrors; i++) {
        shard = json_object_array_get_idx(req->response, i);
        json_object_object_get_ex(shard, "established",
                                 &established);
        int num_established =
            json_object_array_length(established);
        for (int j = 0; j < num_established; j++) {
            item = json_object_array_get_idx(established, j);
            if (j == 0) {
                json_object_object_get_ex(item, "shardHash",
                                          &hash);
                printf("Shard %i: %s\n", i, json_object_get_string(hash));
            }
            json_object_object_get_ex(item, "contract", &contract);
            json_object_object_get_ex(contract, "farmer_id", &node_id);

            const char *node_id_str = json_object_get_string(node_id);
            printf("\tnodeID: %s\n", node_id_str);
        }
        printf("\n\n");
    }

    json_object_put(req->response);

    queue_next_cmd_req(storj_api);
cleanup:
    free(req->path);
    free(req);
    free(work_req);
}

static void delete_file_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    storj_api_t *storj_api = req->handle;
    storj_api->last_cmd_req = storj_api->curr_cmd_req;
    storj_api->rcvd_cmd_resp = "remove-file-resp";

    if (req->status_code == 200 || req->status_code == 204) {
        printf("File was successfully removed from bucket.\n");
    } else if (req->status_code == 401) {
        printf("Invalid user credentials.\n");
        goto cleanup;
    } else {
        printf("Failed to remove file from bucket. (%i)\n", req->status_code);
        goto cleanup;
    }

    json_object_put(req->response);

    queue_next_cmd_req(storj_api);
cleanup:
    free(req->path);
    free(req);
    free(work_req);
}

static void delete_bucket_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    storj_api_t *storj_api = req->handle;
    storj_api->last_cmd_req = storj_api->curr_cmd_req;
    storj_api->rcvd_cmd_resp = "remove-bucket-resp";

    if (req->status_code == 200 || req->status_code == 204)
    {
        printf("Bucket was successfully removed.\n");
    } 
    else if (req->status_code == 401)
    {
        printf("Invalid user credentials.\n");
        goto cleanup;
    } 
    else
    {
        printf("Failed to destroy bucket. (%i)\n", req->status_code);
        goto cleanup;
    }

    json_object_put(req->response);

    queue_next_cmd_req(storj_api);
cleanup:
    free(req->path);
    free(req);
    free(work_req);
}

void get_bucket_id_callback(uv_work_t *work_req, int status)
{
    int ret_status = 0x00;
    assert(status == 0);
    get_buckets_request_t *req = work_req->data;
    storj_api_t *storj_api = req->handle;

    storj_api->last_cmd_req = storj_api->curr_cmd_req;
    storj_api->rcvd_cmd_resp = "get-bucket-id-resp";

    if (req->status_code == 401)
    {
        printf("Invalid user credentials.\n");
        goto cleanup;
    } 
    else if (req->status_code != 200 && req->status_code != 304)
    {
        printf("Request failed with status code: %i\n", req->status_code);
        goto cleanup;
    } 
    else if (req->total_buckets == 0)
    {
        printf("No buckets.\n");
        goto cleanup;
    }

    for (int i = 0; i < req->total_buckets; i++)
    {
        storj_bucket_meta_t *bucket = &req->buckets[i];

        if (strcmp(storj_api->bucket_name, bucket->name) == 0x00)
        {
            printf("ID: %s \tDecrypted: %s \tCreated: %s \tName: %s\n",
                   bucket->id, bucket->decrypted ? "true" : "false",
                   bucket->created, bucket->name);

            /* store the bucket id */
            storj_api->bucket_id = (char *)bucket->id;

            break;
        } 
        else
        {
            if (i >= (req->total_buckets - 1))
            {
                printf("Invalid bucket name. \n");
                goto cleanup;
            }
        }
    }

    queue_next_cmd_req(storj_api);

cleanup:
    storj_free_get_buckets_request(req);
    free(work_req);
}


void list_files_callback(uv_work_t *work_req, int status)
{
    int ret_status = 0;
    assert(status == 0);
    list_files_request_t *req = work_req->data;

    storj_api_t *storj_api = req->handle;
    storj_api->last_cmd_req = storj_api->curr_cmd_req;
    storj_api->rcvd_cmd_resp = "list-files-resp";

    if (req->status_code == 404)
    {
        printf("Bucket id [%s] does not exist\n", req->bucket_id);
        goto cleanup;
    } 
    else if (req->status_code == 400)
    {
        printf("Bucket id [%s] is invalid\n", req->bucket_id);
        goto cleanup;
    } 
    else if (req->status_code == 401)
    {
        printf("Invalid user credentials.\n");
        goto cleanup;
    } 
    else if (req->status_code != 200)
    {
        printf("Request failed with status code: %i\n", req->status_code);
    }

    if (req->total_files == 0)
    {
        printf("No files for bucket.\n");
        goto cleanup;
    }


    FILE *dwnld_list_fd = stdout;
    if ((dwnld_list_fd = fopen("/tmp/dwnld_list.txt", "w")) == NULL)
    {
        printf("[%s][%d] Unable to create download list file\n",
               __FUNCTION__, __LINE__);
        goto cleanup;
    }

    storj_api->file_id = NULL;
    for (int i = 0; i < req->total_files; i++)
    {
        storj_file_meta_t *file = &req->files[i];

        if ((storj_api->file_name != NULL) &&
            (strcmp(storj_api->file_name, file->filename)) == 0x00)
        {
            /* store the file id */
            storj_api->file_id = (char *)file->id;
        }

        printf("ID: %s \tSize: %" PRIu64 " bytes \tDecrypted: %s \tType: %s \tCreated: %s \tName: %s\n",
               file->id,
               file->size,
               file->decrypted ? "true" : "false",
               file->mimetype,
               file->created,
               file->filename);

        fprintf(dwnld_list_fd, "%s:%s\n",file->id, file->filename);
    }

    storj_api->total_files = req->total_files;
    storj_api->xfer_count = 0x01;
    fclose(dwnld_list_fd);
    queue_next_cmd_req(storj_api);

  cleanup:

    storj_free_list_files_request(req);
    free(work_req);
}

void queue_next_cmd_req(storj_api_t *storj_api)
{
    void *handle = storj_api->handle;

    #ifdef debug_enable
    printf("[%s][%d]start !!!! expt resp = %s; rcvd resp = %s \n",
           __FUNCTION__, __LINE__,
            storj_api->excp_cmd_resp, storj_api->rcvd_cmd_resp );
    printf("[%s][%d]last cmd = %s; cur cmd = %s; next cmd = %s\n",
           __FUNCTION__, __LINE__, storj_api->last_cmd_req, 
           storj_api->curr_cmd_req, storj_api->next_cmd_req);
    #endif

    if (strcmp(storj_api->excp_cmd_resp, storj_api->rcvd_cmd_resp) == 0x00)
    {
        if ((storj_api->next_cmd_req != NULL) && 
            (strcmp(storj_api->next_cmd_req, "list-files-req") == 0x00))
        {
            storj_api->curr_cmd_req  = storj_api->next_cmd_req;
            storj_api->next_cmd_req  = storj_api->final_cmd_req;
            storj_api->final_cmd_req = NULL;
            storj_api->excp_cmd_resp = "list-files-resp";

            storj_bridge_list_files(storj_api->env, storj_api->bucket_id, 
                                    storj_api, list_files_callback);
        }
        else if ((storj_api->next_cmd_req != NULL) && 
                 (strcmp(storj_api->next_cmd_req, "remove-bucket-req") == 0x00))
        {
            storj_api->curr_cmd_req  = storj_api->next_cmd_req;
            storj_api->next_cmd_req  = storj_api->final_cmd_req;
            storj_api->final_cmd_req = NULL;
            storj_api->excp_cmd_resp = "remove-bucket-resp";

            storj_bridge_delete_bucket(storj_api->env, storj_api->bucket_id, 
                                       storj_api, delete_bucket_callback);
        }
        else if ((storj_api->next_cmd_req != NULL) && 
                 (strcmp(storj_api->next_cmd_req, "remove-file-req") == 0x00))
        {
            if (storj_api->file_id != NULL)
            {
                printf("[%s][%d]file-name = %s; file-id = %s; bucket-name = %s \n",
                       __FUNCTION__, __LINE__, storj_api->file_name, storj_api->file_id,
                       storj_api->bucket_name);

                storj_api->curr_cmd_req  = storj_api->next_cmd_req;
                storj_api->next_cmd_req  = storj_api->final_cmd_req;
                storj_api->final_cmd_req = NULL;
                storj_api->excp_cmd_resp = "remove-file-resp";

                storj_bridge_delete_file(storj_api->env, storj_api->bucket_id, storj_api->file_id,
                                         storj_api, delete_file_callback);
            }
            else
            {
                printf("\'%s\' file doesn't exists in \'%s\' bucket\n", 
                       storj_api->file_name, storj_api->bucket_name);
            }
        }
        else if ((storj_api->next_cmd_req != NULL) && 
                 (strcmp(storj_api->next_cmd_req, "list-mirrors-req") == 0x00))
        {
            if (storj_api->file_id != NULL)
            {   
                printf("[%s][%d]file-name = %s; file-id = %s; bucket-name = %s \n",
                       __FUNCTION__, __LINE__, storj_api->file_name, storj_api->file_id,
                       storj_api->bucket_name);

                storj_api->curr_cmd_req  = storj_api->next_cmd_req;
                storj_api->next_cmd_req  = storj_api->final_cmd_req;
                storj_api->final_cmd_req = NULL;
                storj_api->excp_cmd_resp = "list-mirrors-resp";

                storj_bridge_list_mirrors(storj_api->env, storj_api->bucket_id, storj_api->file_id,
                                          storj_api, list_mirrors_callback);
            }
            else
            {
                printf("\'%s\' file doesn't exists in \'%s\' bucket\n", 
                       storj_api->file_name, storj_api->bucket_name);
            }
        }
        else if ((storj_api->next_cmd_req != NULL) && 
                 (strcmp(storj_api->next_cmd_req, "upload-file-req") == 0x00))
        {
            storj_api->curr_cmd_req  = storj_api->next_cmd_req;
            storj_api->next_cmd_req  = storj_api->final_cmd_req;
            storj_api->final_cmd_req = NULL;
            storj_api->excp_cmd_resp = "upload-file-resp";

            upload_file(storj_api->env, storj_api->bucket_id, storj_api->file_name, storj_api);
        }
        else if ((storj_api->next_cmd_req != NULL) && 
                 (strcmp(storj_api->next_cmd_req, "verify-upload-files-req") == 0x00))
        {
            storj_api->curr_cmd_req  = storj_api->next_cmd_req;
            storj_api->next_cmd_req  = storj_api->final_cmd_req;
            storj_api->final_cmd_req = NULL;
            storj_api->excp_cmd_resp = "verify-upload-files-resp";

            verify_upload_files(storj_api);
        }
        else if ((storj_api->next_cmd_req != NULL) && 
                 (strcmp(storj_api->next_cmd_req, "upload-files-req") == 0x00))
        {
            storj_api->curr_cmd_req  = storj_api->next_cmd_req;
            storj_api->excp_cmd_resp = "upload-files-resp";

            FILE *file = fopen(storj_api->src_list, "r");

            char line[256][256];
            char *temp;
            int i = 0x00;
            memset(line, 0x00, sizeof(line));

            if (file != NULL)
            {
               while((fgets(line[i],sizeof(line), file)!= NULL)) /* read a line from a file */
                {
                    temp = strrchr(line[i], '\n');
                    if(temp) *temp = '\0';
                    storj_api->src_file = line[i];
                    i++;
                    if(i >= storj_api->xfer_count)
                    {
                        break;
                    }
                }
            }
            fclose(file);

            if (storj_api->xfer_count <= storj_api->total_files)
            {
                /* is it the last file ? */
                if(storj_api->xfer_count == storj_api->total_files)
                {
                    storj_api->next_cmd_req  = storj_api->final_cmd_req;
                    storj_api->final_cmd_req = NULL;
                }

                upload_files(storj_api->env, storj_api->bucket_id, storj_api->src_file, storj_api);
                storj_api->xfer_count++;
            }
            else
            {
                printf("[%s][%d] Invalid xfer counts\n", __FUNCTION__, __LINE__);
                exit(0);
            }
        }
        else if ((storj_api->next_cmd_req != NULL) && 
                 (strcmp(storj_api->next_cmd_req, "download-file-req") == 0x00))
        {
            storj_api->curr_cmd_req  = storj_api->next_cmd_req;
            storj_api->next_cmd_req  = storj_api->final_cmd_req;
            storj_api->final_cmd_req = NULL;
            storj_api->excp_cmd_resp = "download-file-resp";

            if (storj_api->file_id != NULL)
            {
                download_file(storj_api->env, storj_api->bucket_id, storj_api->file_id,
                              storj_api->dst_file, storj_api);
            }
            else
            {
                printf("[%s][%d] File not found!!!\n", __FUNCTION__, __LINE__);
                exit(0);
            }
        }
        else if ((storj_api->next_cmd_req != NULL) && 
                 (strcmp(storj_api->next_cmd_req, "download-files-req") == 0x00))
        {
            storj_api->curr_cmd_req  = storj_api->next_cmd_req;
            storj_api->excp_cmd_resp = "download-file-resp";

            FILE *file = stdout;

            if ((file = fopen("/tmp/dwnld_list.txt", "r")) != NULL)
            {
                char line[256][256];
                char *temp;
                char temp_path[1024];
                int i = 0x00;
                char *token[10];
                int tk_idx= 0x00;
                memset(token, 0x00, sizeof(token));
                memset(temp_path, 0x00, sizeof(temp_path));
                memset(line, 0x00, sizeof(line));
                while((fgets(line[i],sizeof(line), file)!= NULL)) /* read a line from a file */
                {
                    temp = strrchr(line[i], '\n');
                    if(temp) *temp = '\0';
                    i++;
                    if (i >= storj_api->xfer_count)
                    {
                        break;
                    }
                }
                fclose(file);

                /* start tokenizing */
                token[0] = strtok(line[i-1], ":");
                while (token[tk_idx] != NULL)
                {
                    tk_idx++;
                    token[tk_idx] = strtok(NULL, ":");
                }

                if(storj_api->xfer_count <= storj_api->total_files)
                {
                    /* is it the last file ? */
                    if(storj_api->xfer_count == storj_api->total_files)
                    {
                        storj_api->next_cmd_req  = storj_api->final_cmd_req;
                        storj_api->final_cmd_req = NULL;
                    }

                    storj_api->file_id = token[0];
                    strcpy(temp_path, storj_api->file_path);
                    if (storj_api->file_path[(strlen(storj_api->file_path)-1)] != '/')
                    {
                        strcat(temp_path, "/");
                    }
                    strcat(temp_path, token[1]);
                    fprintf(stdout,"*****[%d:%d] downloading file to: %s *****\n", storj_api->xfer_count, storj_api->total_files, temp_path);
                    storj_api->xfer_count++;
                    if (storj_api->file_id != NULL)
                    {
                        download_file(storj_api->env, storj_api->bucket_id, storj_api->file_id, temp_path, storj_api);
                    }
                    else
                    {
                        printf("[%s][%d] File not found!!!\n", __FUNCTION__, __LINE__);
                        exit(0);
                    }
                }
                else
                {
                    printf("[%s][%d] Invalid xfer counts\n", __FUNCTION__, __LINE__);
                    exit(0);
                }
           }
        }
        else
        {
            #ifdef debug_enable
            printf("[%s][%d] **** ALL CLEAN & DONE  *****\n", __FUNCTION__, __LINE__);
            #endif

            exit(0);
        }
    }
    else
    {
        printf("[%s][%d]Oops !!!! expt resp = %s; rcvd resp = %s \n",
               __FUNCTION__, __LINE__,
                storj_api->excp_cmd_resp, storj_api->rcvd_cmd_resp );
        printf("[%s][%d]last cmd = %s; cur cmd = %s; next cmd = %s\n",
               __FUNCTION__, __LINE__, storj_api->last_cmd_req, 
               storj_api->curr_cmd_req, storj_api->next_cmd_req);
    }
}
