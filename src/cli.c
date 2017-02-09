#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#include "storj.h"

#ifndef errno
extern int errno;
#endif

static inline void noop() {};

#define HELP_TEXT "usage: storj [<options>] <command> [<args>]\n\n"     \
    "These are common Storj commands for various situations:\n\n"       \
    "account\n"                                                         \
    "  register\n"                                                      \
    "  import-auth\n"                                                   \
    "  export-auth\n\n"                                                 \
    "working with buckets and files\n"                                  \
    "  list-buckets\n"                                                  \
    "  list-files <bucket-id>\n"                                        \
    "  remove-file <bucket-id> <file-id>\n"                             \
    "  add-bucket <name> \n"                                            \
    "  remove-bucket <bucket-id>\n"                                     \
    "  list-mirrors <bucket-id> file-id>\n\n"                           \
    "downloading and uploading files\n"                                 \
    "  upload-file <bucket-id> <path>\n"                                \
    "  download-file <bucket-id> <file-id> <path>\n\n"                  \
    "bridge api information\n"                                          \
    "  get-info\n\n"                                                    \
    "options:\n"                                                        \
    "  -h, --help                output usage information\n"            \
    "  -v, --version             output the version number\n"           \
    "  -u, --url <url>           set the base url for the api\n"        \
    "  -p, --proxy <url>         set the socks proxy "                  \
    "(e.g. socks5://<host>:<port>)\n"                                   \
    "  -l, --log <level>         set the log level (default 0)\n"       \
    "  -d, --debug               set the debug log level\n\n"

#define CLI_VERSION "libstorj-1.0.0-alpha"

static void json_logger(const char *message, int level, void *handle)
{
    printf("{\"message\": \"%s\", \"level\": %i, \"timestamp\": %lu}\n",
           message, level, storj_util_timestamp());
}

static char *get_home_dir()
{
#ifdef _WIN32
    return getenv("USERPROFILE");
#else
    return getenv("HOME");
#endif
}

static int make_user_directory(char *path)
{
    struct stat st = {0};
    if (stat(path, &st) == -1) {
#if _WIN32
        int mkdir_status = _mkdir(path);
        if (mkdir_status) {
            printf("Unable to create directory %s: code: %i.\n",
                   path,
                   mkdir_status);
            return 1;
        }
#else
        if (mkdir(path, 0700)) {
            printf("Unable to create directory %s: reason: %s\n",
                   path,
                   strerror(errno));
            return 1;
        }
#endif
    }
    return 0;
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

static int get_user_auth_location(char *host, char **root_dir, char **user_file)
{
    char *home_dir = get_home_dir();
    if (home_dir == NULL) {
        return 1;
    }

    int len = strlen(home_dir) + strlen("/.storj/");
    *root_dir = calloc(len + 1, sizeof(char));
    if (!*root_dir) {
        return 1;
    }

    strcpy(*root_dir, home_dir);
    strcat(*root_dir, "/.storj/");

    len = strlen(*root_dir) + strlen(host) + strlen(".json");
    *user_file = calloc(len + 1, sizeof(char));
    if (!*user_file) {
        return 1;
    }

    strcpy(*user_file, *root_dir);
    strcat(*user_file, host);
    strcat(*user_file, ".json");

    return 0;
}

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

static int generate_menmonic(char **mnemonic)
{
    char *strength_str = NULL;
    int strength = 0;
    int status = 0;

    while (strength % 32 || strength < 128 || strength > 256) {
        strength_str = calloc(BUFSIZ, sizeof(char));
        printf("Common mnemonic strengths: 128, 160, 192, 224, 256\n");
        printf("Mnemonic strength (default 256): ");
        get_input(strength_str);

        if (strength_str != NULL) {
            strength = atoi(strength_str);
        }

        free(strength_str);
    }

    if (*mnemonic) {
        free(*mnemonic);
    }

    *mnemonic = calloc(250, sizeof(char));

    int generate_code = storj_mnemonic_generate(strength, mnemonic);
    if (*mnemonic == NULL || generate_code == 0) {
        printf("Failed to generate mnemonic.\n");
        status = 1;
        status = generate_menmonic(mnemonic);
    }

    return status;
}

static void get_password(char *password)
{
    // do not echo the characters
#ifdef _WIN32
    HANDLE hstdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    DWORD prev_mode = 0;
    GetConsoleMode(hstdin, &mode);
    GetConsoleMode(hstdin, &prev_mode);
    SetConsoleMode(hstdin, mode & (~ENABLE_ECHO_INPUT));
#else
    static struct termios prev_terminal;
    static struct termios terminal;

    tcgetattr(STDIN_FILENO, &prev_terminal);

    terminal = prev_terminal;
    terminal.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &terminal);
#endif

    get_input(password);

    // go back to the previous settings
#ifdef _WIN32
    SetConsoleMode(hstdin, prev_mode);
#else
    tcsetattr(STDIN_FILENO, TCSANOW, &prev_terminal);
#endif
}

static int get_password_verify(char *prompt, char *password, int count)
{
    printf("%s", prompt);
    char first_password[BUFSIZ];
    get_password(first_password);

    printf("\nAgain to verify: ");
    char second_password[BUFSIZ];
    get_password(second_password);

    int match = strcmp(first_password, second_password);
    strncpy(password, first_password, BUFSIZ);

    if (match == 0) {
        return 0;
    } else {
        printf("\nPassphrases did not match. ");
        count++;
        if (count > 3) {
            printf("\n");
            return 1;
        }
        printf("Try again...\n");
        return get_password_verify(prompt, password, count);
    }
}

void close_signal(uv_handle_t *handle)
{
    ((void)0);
}

static void file_progress(double progress,
                          uint64_t downloaded_bytes,
                          uint64_t total_bytes,
                          void *handle)
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

static void upload_file_complete(int status, void *handle)
{
    if (status != 0) {
        printf("Upload failure: %s\n", storj_strerror(status));
        exit(status);
    }

    printf("Upload Success!\n");
    exit(0);
}

void upload_signal_handler(uv_signal_t *req, int signum)
{
    storj_upload_state_t *state = req->data;
    storj_bridge_store_file_cancel(state);
    if (uv_signal_stop(req)) {
        printf("Unable to stop signal\n");
    }
    uv_close((uv_handle_t *)req, close_signal);
}

static int upload_file(storj_env_t *env, char *bucket_id, const char *file_path)
{
    FILE *fd = fopen(file_path, "r");

    if (!fd) {
        printf("Invalid file path: %s\n", file_path);
    }

    const char *file_name = get_filename_separator(file_path);

    if (!file_name) {
        file_name = file_path;
    }

    storj_upload_opts_t upload_opts = {
        .shard_concurrency = 3,
        .bucket_id = bucket_id,
        .file_name = file_name,
        .fd = fd
    };

    uv_signal_t sig;
    uv_signal_init(env->loop, &sig);
    uv_signal_start(&sig, upload_signal_handler, SIGINT);

    storj_upload_state_t *state = malloc(sizeof(storj_upload_state_t));
    if (!state) {
        return 1;
    }

    sig.data = state;

    storj_progress_cb progress_cb = (storj_progress_cb)noop;
    if (env->log_options->level == 0) {
        progress_cb = file_progress;
    }

    int status = storj_bridge_store_file(env,
                                         state,
                                         &upload_opts,
                                         NULL,
                                         progress_cb,
                                         upload_file_complete);

    return status;
}

static void download_file_complete(int status, FILE *fd, void *handle)
{
    printf("\n");
    fclose(fd);
    if (status) {
        // TODO send to stderr
        printf("Download failure: %s\n", storj_strerror(status));
        exit(status);
    }
    exit(0);
}

void download_signal_handler(uv_signal_t *req, int signum)
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
    FILE *fd = NULL;

    if (path) {
        fd = fopen(path, "w+");
    } else {
        fd = stdout;
    }

    if (fd == NULL) {
        // TODO send to stderr
        printf("Unable to open %s: %s\n", path, strerror(errno));
        return 1;
    }

    uv_signal_t sig;
    uv_signal_init(env->loop, &sig);
    uv_signal_start(&sig, download_signal_handler, SIGINT);

    storj_download_state_t *state = malloc(sizeof(storj_download_state_t));
    if (!state) {
        return 1;
    }

    sig.data = state;

    storj_progress_cb progress_cb = (storj_progress_cb)noop;
    if (path && env->log_options->level == 0) {
        progress_cb = file_progress;
    }

    int status = storj_bridge_resolve_file(env, state, bucket_id,
                                           file_id, fd, NULL,
                                           progress_cb,
                                           download_file_complete);

    return status;
}

static void list_mirrors_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    if (req->status_code != 200) {
        printf("Request failed with status code: %i\n",
               req->status_code);
    }

    if (req->response == NULL) {
        free(req);
        free(work_req);
        printf("Failed to list mirrors.\n");
        exit(1);
    }

    int num_mirrors = json_object_array_length(req->response);

    struct json_object *shard;
    struct json_object *established;
    struct json_object *available;
    struct json_object *item;
    struct json_object *hash;
    struct json_object *contact;
    struct json_object *address;
    struct json_object *port;
    struct json_object *node_id;

    for (int i = 0; i < num_mirrors; i++) {
        printf("Established\n");
        printf("-----------\n");
        printf("Shard: %i\n", i);
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
                printf("Hash: %s\n", json_object_get_string(hash));
            }
            json_object_object_get_ex(item, "contact", &contact);
            json_object_object_get_ex(contact, "address",
                                      &address);
            json_object_object_get_ex(contact, "port", &port);
            json_object_object_get_ex(contact, "nodeID", &node_id);
            const char *address_str =
                json_object_get_string(address);
            const char *port_str = json_object_get_string(port);
            const char *node_id_str =
                json_object_get_string(node_id);
            printf("\tstorj://%s:%s/%s\n", address_str, port_str, node_id_str);
        }

        printf("\nAvailable\n");
        printf("---------\n");
        printf("Shard: %i\n", i);
        json_object_object_get_ex(shard, "available",
                                 &available);
        int num_available =
            json_object_array_length(available);
        for (int j = 0; j < num_available; j++) {
            item = json_object_array_get_idx(available, j);
            if (j == 0) {
                json_object_object_get_ex(item, "shardHash",
                                          &hash);
                printf("Hash: %s\n", json_object_get_string(hash));
            }
            json_object_object_get_ex(item, "contact", &contact);
            json_object_object_get_ex(contact, "address",
                                      &address);
            json_object_object_get_ex(contact, "port", &port);
            json_object_object_get_ex(contact, "nodeID", &node_id);
            const char *address_str =
                json_object_get_string(address);
            const char *port_str = json_object_get_string(port);
            const char *node_id_str =
                json_object_get_string(node_id);
            printf("\tstorj://%s:%s/%s\n", address_str, port_str, node_id_str);
        }
    }

    json_object_put(req->response);
    free(req);
    free(work_req);
}

static void register_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    if (req->status_code != 201) {
        printf("Request failed with status code: %i\n",
               req->status_code);
        struct json_object *error;
        json_object_object_get_ex(req->response, "error", &error);
        printf("Error: %s\n", json_object_get_string(error));
    } else {
        struct json_object *email;
        json_object_object_get_ex(req->response, "email", &email);
        printf("Successfully registered %s\n", json_object_get_string(email));

        // save credentials
        char *mnemonic = NULL;
        printf("\n");
        generate_menmonic(&mnemonic);
        printf("\n");
        printf("Mnemonic: %s\n", mnemonic);

        if (mnemonic) {
            free(mnemonic);
        }
    }

    json_object_put(req->response);
    free(req);
    free(work_req);
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
                json_object_get_string(filename),
                json_object_get_string(mimetype),
                json_object_get_string(size),
                json_object_get_string(id));
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

    if (req->status_code == 200 || req->status_code == 204) {
        printf("Bucket was successfully removed destroyed.\n");
    } else {
        printf("Failed to destroy bucket. (%i)\n", req->status_code);
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
        printf("ID: \"%s\", Name: %s, Storage: %s, Transfer: %s\n",
               json_object_get_string(id),
               json_object_get_string(name),
               json_object_get_string(storage),
               json_object_get_string(transfer));
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
    printf("ID: \"%s\", Name: %s, Storage: %s, Transfer: %s\n",
           json_object_get_string(id),
           json_object_get_string(name),
           json_object_get_string(storage),
           json_object_get_string(transfer));

    json_object_put(req->response);
    free(req);
    free(work_req);
}

static void get_info_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    if (req->error_code || req->response == NULL) {
        free(req);
        free(work_req);
        if (req->error_code) {
            printf("Request failed, reason: %s\n",
                   curl_easy_strerror(req->error_code));
        } else {
            printf("Failed to get info.\n");
        }
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

    printf("Title:       %s\n", json_object_get_string(title));
    printf("Description: %s\n", json_object_get_string(description));
    printf("Version:     %s\n", json_object_get_string(version));
    printf("Host:        %s\n", json_object_get_string(host));

    json_object_put(req->response);
    free(req);
    free(work_req);
}

static int export_auth(char *host)
{
    int status = 0;
    char *user_file = NULL;
    char *root_dir = NULL;
    char *user = NULL;
    char *pass = NULL;
    char *mnemonic = NULL;
    char *key = NULL;

    if (get_user_auth_location(host, &root_dir, &user_file)) {
        printf("Unable to determine user auth filepath.\n");
        status = 1;
        goto clear_variables;
    }

    if (access(user_file, F_OK) != -1) {
        key = calloc(BUFSIZ, sizeof(char));
        printf("Encryption passphrase: ");
        get_password(key);
        printf("\n\n");

        if (storj_decrypt_read_auth(user_file, key, &user, &pass, &mnemonic)) {
            printf("Unable to read user file.\n");
            status = 1;
            goto clear_variables;
        }

        printf("Username:\t%s\nPassword:\t%s\nMnemonic:\t%s\n",
               user, pass, mnemonic);
    }

clear_variables:
    if (user) {
        free(user);
    }
    if (pass) {
        free(pass);
    }
    if (mnemonic) {
        free(mnemonic);
    }
    if (root_dir) {
        free(root_dir);
    }
    if (user_file) {
        free(user_file);
    }
    if (key) {
        free(key);
    }
    return status;
}

static int set_auth(char *host)
{
    int status = 0;
    char *user = NULL;
    char *pass = NULL;
    char *mnemonic = NULL;
    char *mnemonic_input = NULL;
    char *key = NULL;

    char *user_input = calloc(BUFSIZ, sizeof(char));
    if (user_input == NULL) {
        printf("Unable to allocate buffer\n");
        status = 1;
        goto clear_variables;
    }

    char *user_file = NULL;
    char *root_dir = NULL;
    if (get_user_auth_location(host, &root_dir, &user_file)) {
        printf("Unable to determine user auth filepath.\n");
        status = 1;
        goto clear_variables;
    }

    struct stat st;
    if (stat(user_file, &st) == 0) {
        printf("Would you like to overwrite the current settings?: [y/n] ");
        get_input(user_input);
        while (strcmp(user_input, "y") != 0 && strcmp(user_input, "n") != 0)
        {
            printf("Would you like to overwrite the current settings?: [y/n] ");
            get_input(user_input);
        }

        if (strcmp(user_input, "n") == 0) {
            printf("\nCanceled overwriting of stored credentials.\n");
            status = 1;
            goto clear_variables;
        }
    }

    printf("Bridge username (email): ");
    get_input(user_input);
    int num_chars = strlen(user_input);
    user = calloc(num_chars + 1, sizeof(char));
    if (!user) {
        status = 1;
        goto clear_variables;
    }
    memcpy(user, user_input, num_chars * sizeof(char));

    printf("Password: ");
    pass = calloc(BUFSIZ, sizeof(char));
    if (!pass) {
        status = 1;
        goto clear_variables;
    }
    get_password(pass);
    printf("\n");

    mnemonic_input = calloc(BUFSIZ, sizeof(char));
    if (!mnemonic_input) {
        status = 1;
        goto clear_variables;
    }

    printf("Mnemonic: ");
    get_input(mnemonic_input);
    num_chars = strlen(mnemonic_input);

    mnemonic = calloc(num_chars + 1, sizeof(char));
    if (!mnemonic) {
        status = 1;
        goto clear_variables;
    }
    memcpy(mnemonic, mnemonic_input, num_chars * sizeof(char));

    if (!storj_mnemonic_check(mnemonic)) {
        printf("Mnemonic integrity check failed.\n");
        status = 1;
        goto clear_variables;
    }

    key = calloc(BUFSIZ, sizeof(char));
    if (get_password_verify("Encryption passphrase: ", key, 0)) {
        printf("Unable to store encrypted authentication.\n");
        status = 1;
        goto clear_variables;
    }
    printf("\n");

    if (make_user_directory(root_dir)) {
        status = 1;
        goto clear_variables;
    }

    if (storj_encrypt_write_auth(user_file, key, user, pass, mnemonic)) {
        status = 1;
        printf("Failed to write to disk\n");
        goto clear_variables;
    }

    printf("Successfully stored username, password, and mnemonic.\n");

clear_variables:
    if (user) {
        free(user);
    }
    if (user_input) {
        free(user_input);
    }
    if (pass) {
        free(pass);
    }
    if (mnemonic) {
        free(mnemonic);
    }
    if (mnemonic_input) {
        free(mnemonic_input);
    }
    if (key) {
        free(key);
    }
    if (root_dir) {
        free(root_dir);
    }

    return status;
}

int main(int argc, char **argv)
{
    int status = 0;

    static struct option cmd_options[] = {
        {"url", required_argument,  0, 'u'},
        {"version", no_argument,  0, 'v'},
        {"proxy", required_argument,  0, 'p'},
        {"log", required_argument,  0, 'l'},
        {"debug", no_argument,  0, 'd'},
        {"help", no_argument,  0, 'h'},
        {0, 0, 0, 0}
    };

    int index = 0;

    char *storj_bridge = getenv("STORJ_BRIDGE");
    int c;
    int log_level = 0;

    char *proxy = getenv("STORJ_PROXY");

    while ((c = getopt_long_only(argc, argv, "hdl:p:vVu:",
                                 cmd_options, &index)) != -1) {
        switch (c) {
            case 'u':
                storj_bridge = optarg;
                break;
            case 'p':
                proxy = optarg;
                break;
            case 'l':
                log_level = atoi(optarg);
                break;
            case 'd':
                log_level = 4;
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

    if (log_level > 4 || log_level < 0) {
        printf("Invalid log level\n");
        return 1;
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

    if (strcmp(command, "login") == 0 || strcmp(command, "import-auth") == 0) {
        return set_auth(host);
    }

    if (strcmp(command, "export-auth") == 0) {
        return export_auth(host);
    }

    // initialize event loop and environment
    storj_env_t *env = NULL;

    storj_http_options_t http_options = {
        .user_agent = CLI_VERSION
    };

    storj_log_options_t log_options = {
        .logger = json_logger,
        .level = log_level
    };

    if (proxy) {
        http_options.proxy_url = proxy;
    } else {
        http_options.proxy_url = NULL;
    }

    if (strcmp(command, "get-info") == 0) {
        printf("Storj bridge: %s\n\n", storj_bridge);

        storj_bridge_options_t options = {
            .proto = proto,
            .host  = host,
            .port  = port,
            .user  = NULL,
            .pass  = NULL
        };

        env = storj_init_env(&options, NULL, &http_options, &log_options);
        if (!env) {
            return 1;
        }

        storj_bridge_get_info(env, NULL, get_info_callback);

    } else if(strcmp(command, "register") == 0) {
        storj_bridge_options_t options = {
            .proto = proto,
            .host  = host,
            .port  = port,
            .user  = NULL,
            .pass  = NULL
        };

        env = storj_init_env(&options, NULL, &http_options, &log_options);
        if (!env) {
            return 1;
        }

        char *user = calloc(BUFSIZ, sizeof(char));
        if (!user) {
            return 1;
        }
        printf("Bridge username (email): ");
        get_input(user);

        printf("Password: ");
        char *pass = calloc(BUFSIZ, sizeof(char));
        if (!pass) {
            return 1;
        }
        get_password(pass);
        printf("\n");

        storj_bridge_register(env, user, pass, NULL, register_callback);
    } else {

        char *user_file = NULL;
        char *root_dir = NULL;
        if (get_user_auth_location(host, &root_dir, &user_file)) {
            printf("Unable to determine user auth filepath.\n");
            return 1;
        }

        // We aren't using root dir so free it
        free(root_dir);

        // First, get auth from environment variables
        char *user = getenv("STORJ_BRIDGE_USER");
        char *pass = getenv("STORJ_BRIDGE_PASS");
        char *mnemonic = getenv("STORJ_MNEMONIC");
        char *keypass = getenv("STORJ_KEYPASS");

        // Second, try to get from encrypted user file
        if ((!user || !pass || !mnemonic) && access(user_file, F_OK) != -1) {

            char *key = NULL;
            if (keypass) {
                key = calloc(strlen(keypass) + 1, sizeof(char));
                if (!key) {
                    return 1;
                }
                strcpy(key, keypass);
            } else {
                key = calloc(BUFSIZ, sizeof(char));
                if (!key) {
                    return 1;
                }
                printf("Encryption passphrase: ");
                get_password(key);
                printf("\n");
            }
            char *file_user = NULL;
            char *file_pass = NULL;
            char *file_mnemonic = NULL;
            if (storj_decrypt_read_auth(user_file, key, &file_user,
                                        &file_pass, &file_mnemonic)) {
                printf("Unable to read user file. Invalid keypass or path.\n");
                goto end_program;
            }

            if (!user && file_user) {
                user = file_user;
            }

            if (!pass && file_pass) {
                pass = file_pass;
            }

            if (!mnemonic && file_mnemonic) {
                mnemonic = file_mnemonic;
            }

        }

        // Third, ask for authentication
        if (!user) {
            char *user_input = malloc(BUFSIZ);
            if (user_input == NULL) {
                return 1;
            }
            printf("Bridge username (email): ");
            get_input(user_input);
            int num_chars = strlen(user_input);
            user = calloc(num_chars + 1, sizeof(char));
            if (!user) {
                return 1;
            }
            memcpy(user, user_input, num_chars);
            free(user_input);
        }

        if (!pass) {
            printf("Bridge password: ");
            pass = calloc(BUFSIZ, sizeof(char));
            if (!pass) {
                return 1;
            }
            get_password(pass);
            printf("\n");
        }

        if (!mnemonic) {
            printf("Encryption mnemonic: ");
            mnemonic = calloc(BUFSIZ, sizeof(char));
            if (!mnemonic) {
                return 1;
            }
            get_password(mnemonic);
            printf("\n");
        }


        storj_bridge_options_t options = {
            .proto = proto,
            .host  = host,
            .port  = port,
            .user  = user,
            .pass  = pass
        };

        storj_encrypt_options_t encrypt_options = {
            .mnemonic = mnemonic,
            .tmp_path = NULL
        };

        env = storj_init_env(&options, &encrypt_options,
                             &http_options, &log_options);
        if (!env) {
            status = 1;
            goto end_program;
        }

        if (strcmp(command, "download-file") == 0) {
            char *bucket_id = argv[command_index + 1];
            char *file_id = argv[command_index + 2];
            char *path = argv[command_index + 3];

            if (!bucket_id || !file_id) {
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

            storj_bridge_list_files(env, bucket_id, NULL, list_files_callback);
        } else if (strcmp(command, "add-bucket") == 0) {
            char *bucket_name = argv[command_index + 1];

            if (!bucket_name) {
                printf(HELP_TEXT);
                status = 1;
                goto end_program;
            }

            storj_bridge_create_bucket(env, bucket_name,
                                       NULL, create_bucket_callback);

        } else if (strcmp(command, "remove-bucket") == 0) {
            char *bucket_id = argv[command_index + 1];

            if (!bucket_id) {
                printf(HELP_TEXT);
                status = 1;
                goto end_program;
            }

            storj_bridge_delete_bucket(env, bucket_id, NULL,
                                       delete_bucket_callback);

        } else if (strcmp(command, "remove-file") == 0) {
            char *bucket_id = argv[command_index + 1];
            char *file_id = argv[command_index + 2];

            if (!bucket_id || !file_id) {
                printf(HELP_TEXT);
                status = 1;
                goto end_program;
            }
            storj_bridge_delete_file(env, bucket_id, file_id,
                                     NULL, delete_file_callback);

        } else if (strcmp(command, "list-buckets") == 0) {
            storj_bridge_get_buckets(env, NULL, get_buckets_callback);
        } else if (strcmp(command, "list-mirrors") == 0) {
            char *bucket_id = argv[command_index + 1];
            char *file_id = argv[command_index + 2];

            if (!bucket_id || !file_id) {
                printf(HELP_TEXT);
                status = 1;
                goto end_program;
            }
            storj_bridge_list_mirrors(env, bucket_id, file_id,
                                      NULL, list_mirrors_callback);
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
        storj_destroy_env(env);
    }
    return status;
}
