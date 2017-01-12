#include <errno.h>
#include <termios.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

#include "storj.h"

extern int errno;

#define HELP_TEXT "usage: storj [<options>] <command> [<args>]\n\n"     \
    "These are common Storj commands for various situations:\n\n"       \
    "working with buckets and files\n"                                  \
    "  list-buckets\n"                                                  \
    "  list-files <bucket-id>\n"                                        \
    "  remove-file <bucket-id> <file-id>\n"                             \
    "  add-bucket <name> \n"                                            \
    "  remove-bucket <bucket-id>\n\n"                                   \
    "downloading and uploading files\n"                                 \
    "  upload-file <bucket-id> <path>\n"                                \
    "  download-file <bucket-id> <file-id> <path>\n\n"                  \
    "bridge api information\n"                                          \
    "  get-info\n\n"                                                    \
    "options:\n"                                                        \
    "  -h, --help                output usage information\n"            \
    "  -v, --version             output the version number\n"           \
    "  -u, --url <url>           set the base url for the api\n\n"      \

#define CLI_VERSION "libstorj-1.0.0-alpha"

static void get_password(char *password)
{
    static struct termios prev_terminal;
    static struct termios terminal;

    tcgetattr(STDIN_FILENO, &prev_terminal);

    // do not echo the characters
    terminal = prev_terminal;
    terminal.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &terminal);

    if (fgets(password, BUFSIZ, stdin) == NULL) {
        password[0] = '\0';
    } else {
        password[strlen(password)-1] = '\0';
    }

    // go back to the previous settings
    tcsetattr(STDIN_FILENO, TCSANOW, &prev_terminal);
}

static void upload_file_progress(double progress,
                                 uint64_t uploaded_bytes,
                                 uint64_t total_bytes)
{
    // TODO assersions
}

static void upload_file_complete(int status)
{
    if (status != 0) {
        printf("Upload failure: %s\n", storj_strerror(status));
        exit(status);
    }

    printf("Upload Success!\n");
    exit(0);
}

static int upload_file(storj_env_t *env, char *bucket_id, char *file_path)
{
    char *mnemonic = getenv("STORJ_MNEMONIC");
    if (!mnemonic) {
        printf("Set your STORJ_MNEMONIC\n");
        exit(1);
        // "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    }

    storj_upload_opts_t upload_opts = {
        .file_concurrency = 1,
        .shard_concurrency = 3,
        .bucket_id = bucket_id,
        .file_path = file_path,
        .key_pass = "password",
        .mnemonic = mnemonic
    };

    int status = storj_bridge_store_file(env, &upload_opts,
                                     upload_file_progress,
                                     upload_file_complete);

    return status;
}


static void download_file_progress(double progress,
                                   uint64_t downloaded_bytes,
                                   uint64_t total_bytes)
{
    int bar_width = 70;

    printf("\r[");
    int pos = bar_width * progress;
    for (int i = 0; i < bar_width; ++i) {
        if (i < pos) {
            printf("=");
        } else if (i == pos) {
            printf(">");
        } else {
            printf(" ");
        }
    }
    printf("] %.*f%%", 2, progress * 100);
    fflush(stdout);
}

static void download_file_complete(int status, FILE *fd)
{
    printf("\n");
    fclose(fd);
    if (status) {
        printf("Download failure: %s\n", storj_strerror(status));
        exit(status);
    }
    exit(0);
}

void close_signal(uv_handle_t *handle)
{
    ((void)0);
}

void signal_handler(uv_signal_t *req, int signum)
{
    storj_download_state_t *state = req->data;
    storj_bridge_resolve_file_cancel(state);
    if (uv_signal_stop(req)) {
        printf("Unable to stop signal\n");
    }
    uv_close((uv_handle_t *)req, close_signal);
}

static int download_file(storj_env_t *env, char *bucket_id,
                         char *file_id, char *path)
{
    FILE *fd = fopen(path, "w+");

    if (fd == NULL) {
        printf("Unable to open %s: %s\n", path, strerror(errno));
        return 1;
    }

    uv_signal_t sig;
    uv_signal_init(env->loop, &sig);
    uv_signal_start(&sig, signal_handler, SIGINT);

    storj_download_state_t *state = malloc(sizeof(storj_download_state_t));

    sig.data = state;

    int status = storj_bridge_resolve_file(env, state, bucket_id, file_id, fd,
                                           download_file_progress,
                                           download_file_complete);

    return status;

}

static void list_files_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    if (req->status_code != 200) {
        printf("Request failed with status code: %i\n", req->status_code);
    }

    if (req->response == NULL) {
        free(req);
        free(work_req);
        printf("Failed to list files.\n");
        exit(1);
    }
    int num_files = json_object_array_length(req->response);

    if (num_files == 0) {
        printf("No files for bucket");
    }

    struct json_object *file;
    struct json_object *filename;
    struct json_object *mimetype;
    struct json_object *size;
    struct json_object *id;

    for (int i = 0; i < num_files; i++) {
        file = json_object_array_get_idx(req->response, i);
        json_object_object_get_ex(file, "filename", &filename);
        json_object_object_get_ex(file, "mimetype", &mimetype);
        json_object_object_get_ex(file, "size", &size);
        json_object_object_get_ex(file, "id", &id);
        // print out the name attribute
        printf("Name: %s, Type: %s, Size: %s bytes, ID: %s\n",
                json_object_to_json_string(filename),
                json_object_to_json_string(mimetype),
                json_object_to_json_string(size),
                json_object_to_json_string(id));
    }

    json_object_put(req->response);
    free(req);
    free(work_req);
}

static void delete_file_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    if (req->status_code == 200) {
        printf("File was successfully removed from bucket.\n");
    } else {
        printf("Failed to remove file from bucket.\n");
    }

    free(req);
    free(work_req);
}

static void delete_bucket_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    if (req->status_code == 200) {
        printf("Bucket was successfully removed destroyed.\n");
    } else {
        printf("Failed to destroy bucket.\n");
    }

    free(req);
    free(work_req);
}

static void get_buckets_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    if (req->status_code != 200) {
        printf("Request failed with status code: %i\n", req->status_code);
    }

    if (req->response == NULL) {
        free(req);
        free(work_req);
        printf("Failed to list buckets.\n");
        exit(1);
    }

    int num_buckets = json_object_array_length(req->response);
    struct json_object *bucket;
    struct json_object *id;
    struct json_object *name;
    struct json_object *storage;
    struct json_object *transfer;

    for (int i = 0; i < num_buckets; i++) {
        bucket = json_object_array_get_idx(req->response, i);
        json_object_object_get_ex(bucket, "id", &id);
        json_object_object_get_ex(bucket, "name", &name);
        json_object_object_get_ex(bucket, "storage", &storage);
        json_object_object_get_ex(bucket, "transfer", &transfer);
        // print out the name attribute
        printf("ID: %s, Name: %s, Storage: %s, Transfer: %s\n",
                json_object_to_json_string(id),
                json_object_to_json_string(name),
                json_object_to_json_string(storage),
                json_object_to_json_string(transfer));
    }

    json_object_put(req->response);
    free(req);
    free(work_req);
}

static void create_bucket_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    if (req->response == NULL) {
        free(req);
        free(work_req);
        printf("Failed to add bucket.\n");
        exit(1);
    }

    struct json_object *bucket;
    struct json_object *id;
    struct json_object *name;
    struct json_object *storage;
    struct json_object *transfer;

    json_object_object_get_ex(req->response, "id", &id);
    json_object_object_get_ex(req->response, "name", &name);
    json_object_object_get_ex(req->response, "storage", &storage);
    json_object_object_get_ex(req->response, "transfer", &transfer);
    // print out the name attribute
    printf("ID: %s, Name: %s, Storage: %s, Transfer: %s\n",
            json_object_to_json_string(id),
            json_object_to_json_string(name),
            json_object_to_json_string(storage),
            json_object_to_json_string(transfer));

    json_object_put(req->response);
    free(req);
    free(work_req);
}

static void get_info_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    if (req->response == NULL) {
        free(req);
        free(work_req);
        printf("Failed to get info.\n");
        exit(1);
    }

    struct json_object *info;
    json_object_object_get_ex(req->response, "info", &info);

    struct json_object *title;
    json_object_object_get_ex(info, "title", &title);
    struct json_object *description;
    json_object_object_get_ex(info, "description", &description);
    struct json_object *version;
    json_object_object_get_ex(info, "version", &version);
    struct json_object *host;
    json_object_object_get_ex(req->response, "host", &host);

    printf("Title:       %s\n", json_object_to_json_string(title));
    printf("Description: %s\n", json_object_to_json_string(description));
    printf("Version:     %s\n", json_object_to_json_string(version));
    printf("Host:        %s\n", json_object_to_json_string(host));

    json_object_put(req->response);
    free(req);
    free(work_req);
}

int main(int argc, char **argv)
{
    int status = 0;

    static struct option cmd_options[] = {
        {"url", required_argument,  0, 'u'},
        {"version", no_argument,  0, 'v'},
        {"help", no_argument,  0, 'h'},
        {0, 0, 0, 0}
    };

    int index = 0;

    char *storj_bridge = getenv("STORJ_BRIDGE");
    int c;

    while ((c = getopt_long(argc, argv, "hvVu:", cmd_options, &index)) != -1) {
        switch (c) {
            case 'u':
                storj_bridge = optarg;
                break;
            case 'V':
            case 'v':
                printf(CLI_VERSION "\n\n");
                exit(0);
                break;
            case 'h':
                printf(HELP_TEXT);
                exit(0);
                break;
        }
    }

    int command_index = optind;

    char *command = argv[command_index];
    if (!command) {
        printf(HELP_TEXT);
        return 0;
    }

    if (!storj_bridge) {
        storj_bridge = "https://api.storj.io:443/";
    }

    // Parse the host, part and proto from the storj bridge url
    char proto[6];
    char host[100];
    int port = 443;
    sscanf(storj_bridge, "%5[^://]://%99[^:/]:%99d", proto, host, &port);

    // initialize event loop and environment
    storj_env_t *env;

    storj_http_options_t http_options = {
        .user_agent = CLI_VERSION
    };

    if (strcmp(command, "get-info") == 0) {

        printf("Storj bridge: %s\n\n", storj_bridge);

        storj_bridge_options_t options = {
            .proto = proto,
            .host  = host,
            .port  = port,
            .user  = NULL,
            .pass  = NULL
        };

        env = storj_init_env(&options, NULL, &http_options);
        if (!env) {
            return 1;
        }

        storj_bridge_get_info(env, get_info_callback);

    } else {

        // Get the bridge user
        char *user = getenv("STORJ_BRIDGE_USER");
        if (!user) {
            char *user_input;
            size_t user_input_size = 1024;
            size_t num_chars;
            user_input = calloc(user_input_size, sizeof(char));
            if (user_input == NULL) {
                printf("Unable to allocate buffer");
                exit(1);
            }
            printf("Bridge username (email): ");
            num_chars = getline(&user_input, &user_input_size, stdin);
            user = calloc(num_chars - 1, sizeof(char));
            memcpy(user, user_input, num_chars * sizeof(char) - 1);
        }

        // Get the bridge password
        char *pass = getenv("STORJ_BRIDGE_PASS");
        if (!pass) {
            printf("Bridge password: ");
            pass = calloc(BUFSIZ, sizeof(char));
            get_password(pass);
            printf("\n");
        }

        storj_bridge_options_t options = {
            .proto = proto,
            .host  = host,
            .port  = port,
            .user  = user,
            .pass  = pass
        };

        char *mnemonic = getenv("STORJ_MNEMONIC");

        if (!mnemonic) {
            printf("Encryption mnemonic: ");
            mnemonic = calloc(BUFSIZ, sizeof(char));
            get_password(mnemonic);
            printf("\n");
        }

        storj_encrypt_options_t encrypt_options = {
            .mnemonic = mnemonic
        };

        env = storj_init_env(&options, &encrypt_options, &http_options);
        if (!env) {
            status = 1;
            goto end_program;
        }

        if (strcmp(command, "download-file") == 0) {
            char *bucket_id = argv[command_index + 1];
            char *file_id = argv[command_index + 2];
            char *path = argv[command_index + 3];

            if (!bucket_id || !file_id || !path) {
                printf(HELP_TEXT);
                status = 1;
                goto end_program;
            }

            if (download_file(env, bucket_id, file_id, path)) {
                status = 1;
                goto end_program;
            }
        } else if (strcmp(command, "upload-file") == 0) {
            char *bucket_id = argv[command_index + 1];
            char *path = argv[command_index + 2];

            if (!bucket_id || !path) {
                printf(HELP_TEXT);
                status = 1;
                goto end_program;
            }

            if (upload_file(env, bucket_id, path)) {
                status = 1;
                goto end_program;
            }
        } else if (strcmp(command, "list-files") == 0) {
            char *bucket_id = argv[command_index + 1];

            if (!bucket_id) {
                printf(HELP_TEXT);
                status = 1;
                goto end_program;
            }

            storj_bridge_list_files(env, bucket_id, list_files_callback);
        } else if (strcmp(command, "add-bucket") == 0) {
            char *bucket_name = argv[command_index + 1];

            if (!bucket_name) {
                printf(HELP_TEXT);
                status = 1;
                goto end_program;
            }

            storj_bridge_create_bucket(env, bucket_name,
                                       create_bucket_callback);

        } else if (strcmp(command, "remove-bucket") == 0) {
            char *bucket_id = argv[command_index + 1];

            if (!bucket_id) {
                printf(HELP_TEXT);
                status = 1;
                goto end_program;
            }

            storj_bridge_delete_bucket(env, bucket_id, delete_bucket_callback);
        } else if (strcmp(command, "remove-file") == 0) {
            char *bucket_id = argv[command_index + 1];
            char *file_id = argv[command_index + 2];

            if (!bucket_id || !file_id) {
                printf(HELP_TEXT);
                status = 1;
                goto end_program;
            }
            storj_bridge_delete_file(env, bucket_id, file_id,
                                     delete_file_callback);

        } else if (strcmp(command, "list-buckets") == 0) {
            storj_bridge_get_buckets(env, get_buckets_callback);
        } else {
            printf("'%s' is not a storj command. See 'storj --help'\n\n",
                   command);
            status = 1;
            goto end_program;
        }
    }

    // run all queued events
    if (uv_run(env->loop, UV_RUN_DEFAULT)) {
        status = 1;
        goto end_program;
    }

    // shutdown
    int uv_status = uv_loop_close(env->loop);
    if (uv_status == UV_EBUSY) {
        status = 1;
        goto end_program;
    }

end_program:
    if (env) {
        free(env->loop);
        free(env);
    }
    return status;
}
