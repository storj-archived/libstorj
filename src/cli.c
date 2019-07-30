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
#include "crypto.h"
#include "cli_callback.c"

//#define debug_enable

#define STORJ_THREADPOOL_SIZE "64"

#define STORJ_CLEANUP_SET_STATUS_IF_LAST_ERROR(value) \
if (strcmp("", *STORJ_LAST_ERROR) != 0) { \
    status = value; \
    goto clean_variables; \
}\

typedef struct {
    char *addr;
    char *apikey;
    char *enc_access;
    char *user_passphrase;
} user_options_t;

#ifndef errno
extern int errno;
#endif


#define HELP_TEXT "usage: storj [<options>] <command> [<args>]\n\n"     \
    "These are common Storj commands for various situations:\n\n"       \
    "setting up user profiles:\n"                                       \
    "  import-keys                   import existing user\n"            \
    "  export-keys                   export bridge user, password and " \
    "encryption keys\n\n"                                               \
    "unix style commands:\n"                                            \
    "  ls                            lists the available buckets\n"     \
    "  ls <bucket-name>              lists the files in a bucket\n"     \
    "  cp [-rR] <path> <uri>         upload files to a bucket "         \
    "(e.g. storj cp -[rR] /<some-dir>/* storj://<bucket-name>/)\n"      \
    "  cp [-rR] <uri> <path>         download files from a bucket "     \
    "(e.g. storj cp -[rR] storj://<bucket-name>/ /<some-dir>/)\n"       \
    "  mkbkt <bucket-name>           make a bucket\n"                   \
    "  rm <bucket-name> <file-name>  remove a file from a bucket\n"     \
    "  rm <bucket-name>              remove a bucket\n"                 \
    "working with buckets and files:\n"                                 \
    "  list-buckets\n"                                                  \
    "  list-files <bucket-id>\n"                                        \
    "  remove-file <bucket-id> <file-id>\n"                             \
    "  remove-bucket <bucket-id>\n"                                     \
    "  add-bucket <name> \n"                                            \
    "  get-bucket-id <bucket-name>\n\n"                                 \
    "uploading files:\n"                                                \
    "  upload-file <bucket-id> <path>\n\n"                              \
    "downloading files:\n"                                              \
    "  download-file <bucket-id> <file-id> <directory path/ new file name>\n\n"                  \
    "options:\n"                                                        \
    "  -h, --help                    output usage information\n"        \
    "  -v, --version                 output the version number\n"       \
    "  -u, --url <url>               set the base url for the api\n"    \
    "(e.g. <[protocol://][user:password@]proxyhost[:port]>)\n"          \
    "  -l, --log <level>             set the log level (default 0)\n"   \
    "  -d, --debug                   set the debug log level\n\n"       \
    "environment variables:\n"                                          \
    "  STORJ_KEYPASS                 imported user settings passphrase\n" \
    "  STORJ_BRIDGE                  the satellite (bridge) host "      \
    "(e.g. https://api.storj.io)\n"                                     \
    "  STORJ_API_KEY                 project API key\n"                 \
    "  STORJ_ENCRYPTION_KEY          encryption key\n\n"


#define CLI_VERSION "libstorj-2.0.0-beta2"

static int check_file_path(char *file_path)
{
    struct stat sb;

    if (stat(file_path, &sb) == -1) {
        perror("stat");
        return CLI_NO_SUCH_FILE_OR_DIR;
    }

    switch (sb.st_mode & S_IFMT) {
        case S_IFBLK:
            printf("block device\n");
            break;
        case S_IFCHR:
            printf("character device\n");
            break;
        case S_IFDIR:
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
#ifdef S_IFSOCK
        case S_IFSOCK:
            printf("socket\n");
            break;
#endif
        default:
            printf("unknown?\n");
            break;
    }

    #if ENABLE_FILE_DETAILS
    printf("I-node number:            %ld\n", (long)sb.st_ino);

    printf("Mode:                     %lo (octal)\n",
           (unsigned long)sb.st_mode);

    printf("Link count:               %ld\n", (long)sb.st_nlink);
    printf("Ownership:                UID=%ld   GID=%ld\n",
           (long)sb.st_uid, (long)sb.st_gid);

    printf("Preferred I/O block size: %ld bytes\n",
           (long)sb.st_blksize);
    printf("File size:                %lld bytes\n",
           (long long)sb.st_size);
    printf("Blocks allocated:         %lld\n",
           (long long)sb.st_blocks);

    printf("Last status change:       %s", ctime(&sb.st_ctime));
    printf("Last file access:         %s", ctime(&sb.st_atime));
    printf("Last file modification:   %s", ctime(&sb.st_mtime));
    #endif

    return CLI_UNKNOWN_FILE_ATTR;
}


static int strpos(char *str, char *sub_str)
{
  /* find first        occurance of substring in string */
        char *sub_str_pos=strstr(str,sub_str);

  /* if null return -1 , otherwise return substring address - base address */
        return sub_str_pos == NULL ?  -1 :  (sub_str_pos - str );
}

static int validate_cmd_tokenize(char *cmd_str, char *str_token[])
{
    char sub_str[] = "storj://";
    int i = 0x00;   /* num of tokens */

    int ret = strpos(cmd_str, sub_str);
    if (ret == -1) {
        printf("Invalid Command Entry (%d), \ntry ... storj://<bucket_name>/<file_name>\n", ret);
    }

    if (ret == 0x00) {
        /* start tokenizing */
        str_token[0] = strtok(cmd_str, "/");
        while (str_token[i] != NULL) {
            i++;
            str_token[i] = strtok(NULL, "/");
        }
    } else {
        i = ret;
    }

    return i;
}


static void json_logger(const char *message, int level, void *handle)
{
    printf("{\"message\": \"%s\", \"level\": %i, \"timestamp\": %" PRIu64 "}\n",
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

static int enc_access_from_passphrase(ProjectRef project_ref,
                                              const char *passphrase,
                                              char **enc_access_str)
{
    uint8_t *salted_key = project_salted_key_from_passphrase(project_ref,
                                                             strdup(passphrase),
                                                             STORJ_LAST_ERROR);
    STORJ_RETURN_IF_LAST_ERROR(1);

    EncryptionAccessRef encryption_access = new_encryption_access_with_default_key(salted_key);
    *enc_access_str = serialize_encryption_access(encryption_access, STORJ_LAST_ERROR);
    free(salted_key);
    STORJ_RETURN_IF_LAST_ERROR(1);
}

static int generate_enc_access(storj_bridge_options_t *bridge_opts, const char *passphrase,
                               char **enc_access_str)
{
    storj_log_options_t log_opts = {
            .level = 2
    };
    storj_env_t *env = storj_init_env(bridge_opts, NULL, NULL, &log_opts);
    STORJ_RETURN_IF_LAST_ERROR(1);
    if (!env) {
        return 1;
    }

    return enc_access_from_passphrase(env->project_ref, passphrase, enc_access_str);
}

static int get_password(char *password, int mask)
{
    int max_pass_len = 512;

#ifdef _WIN32
    HANDLE hstdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    DWORD prev_mode = 0;
    GetConsoleMode(hstdin, &mode);
    GetConsoleMode(hstdin, &prev_mode);
    SetConsoleMode(hstdin, mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT));
#else
    static struct termios prev_terminal;
    static struct termios terminal;

    tcgetattr(STDIN_FILENO, &prev_terminal);

    memcpy (&terminal, &prev_terminal, sizeof(struct termios));
    terminal.c_lflag &= ~(ICANON | ECHO);
    terminal.c_cc[VTIME] = 0;
    terminal.c_cc[VMIN] = 1;
    tcsetattr(STDIN_FILENO, TCSANOW, &terminal);
#endif

    size_t idx = 0;         /* index, number of chars in read   */
    int c = 0;

    const char BACKSPACE = 8;
    const char RETURN = 13;

    /* read chars from fp, mask if valid char specified */
#ifdef _WIN32
    long unsigned int char_read = 0;
    while ((ReadConsole(hstdin, &c, 1, &char_read, NULL) && c != '\n' && c != RETURN && c != EOF && idx < max_pass_len - 1) ||
            (idx == max_pass_len - 1 && c == BACKSPACE))
#else
    while (((c = fgetc(stdin)) != '\n' && c != EOF && idx < max_pass_len - 1) ||
            (idx == max_pass_len - 1 && c == 127))
#endif
    {
        if (c != 127 && c != BACKSPACE) {
            if (31 < mask && mask < 127)    /* valid ascii char */
                fputc(mask, stdout);
            password[idx++] = c;
        } else if (idx > 0) {         /* handle backspace (del)   */
            if (31 < mask && mask < 127) {
                fputc(0x8, stdout);
                fputc(' ', stdout);
                fputc(0x8, stdout);
            }
            password[--idx] = 0;
        }
    }
    password[idx] = 0; /* null-terminate   */

    // go back to the previous settings
#ifdef _WIN32
    SetConsoleMode(hstdin, prev_mode);
#else
    tcsetattr(STDIN_FILENO, TCSANOW, &prev_terminal);
#endif

    return idx; /* number of chars in passwd    */
}

static int get_password_verify(char *prompt, char *password, int count)
{
    printf("%s", prompt);
    char first_password[BUFSIZ];
    get_password(first_password, '*');

    printf("\nAgain to verify: ");
    char second_password[BUFSIZ];
    get_password(second_password, '*');

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

static int import_keys(user_options_t *options)
{
    storj_bridge_options_t bridge_opts = {
            .addr = strdup(options->addr),
    };

    int status = 0;
    bridge_opts.apikey = bridge_opts.apikey ?
            strdup(bridge_opts.apikey) : calloc(BUFSIZ, sizeof(char));
    char *enc_access_str = options->enc_access ?
        strdup(options->enc_access): NULL;
    char *user_passphrase = options->user_passphrase ?
            strdup(options->user_passphrase) : NULL;
    char *user_file = NULL;
    char *root_dir = NULL;
    char *new_enc_passphrase = calloc(BUFSIZ, sizeof(char));
    char *user_input = calloc(BUFSIZ, sizeof(char));
    int num_chars;

    // TODO: apikey validation?
    if (!bridge_opts.apikey || strcmp("", bridge_opts.apikey) == 0) {
        printf("Project API key: ");
        get_input(bridge_opts.apikey);
        printf("\n");
        num_chars = strlen(bridge_opts.apikey);

        if (num_chars == 0) {
            // TODO: add link
            printf("Project API key required. See <link here>\n");
            status = 1;
            goto clear_variables;
        }
    }

    if (user_input == NULL) {
        printf("Unable to allocate buffer\n");
        status = 1;
        goto clear_variables;
    }

    if (get_user_auth_location(bridge_opts.addr, &root_dir, &user_file)) {
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

    if (!enc_access_str) {
        enc_access_str = calloc(BUFSIZ, sizeof(char));

        printf("Enter your serialized encryption key (leave blank to generate new): ");
        get_input(enc_access_str);
        num_chars = strlen(enc_access_str);
        printf("\n");

        if (num_chars == 0) {
            if (0 != get_password_verify("Enter a passphrase to generate "
                                              "a new root key for your "
                                              "encryption key: ",
                                              new_enc_passphrase, 0)) {
                printf("Giving up.\n");
                status = 1;
                goto clear_variables;
            };

            if (0 != generate_enc_access(&bridge_opts, new_enc_passphrase,
                                         &enc_access_str)) {
                strcmp("", *STORJ_LAST_ERROR) != 0 ?
                    printf("An error occurred while generating: %s\n", *STORJ_LAST_ERROR) :
                    printf("Unable to generate new encryption key.");
                status = 1;
                goto clear_variables;
            }

            printf("\n");

            printf("Serialized encryption access key: %s\n", enc_access_str);
            printf("\n");
            printf("Please make sure to backup this key in a safe location. " \
                   "If the key is lost, the data uploaded will also be lost.\n\n");

        }

        // NB: check integrity of encryption access
        EncryptionAccessRef enc_access_ref = parse_encryption_access(enc_access_str, STORJ_LAST_ERROR);
        if (strcmp("", *STORJ_LAST_ERROR)) {
            printf("%s\n", *STORJ_LAST_ERROR);
            status = 1;
            goto clear_variables;
        }
    }

    if (!user_passphrase) {
        user_passphrase = calloc(BUFSIZ, sizeof(char));
        printf("We now need to save these settings. Please enter a passphrase" \
       " to lock your settings.\n\n");
        if (get_password_verify("Unlock passphrase: ", user_passphrase, 0)) {
            printf("Unable to store encrypted authentication.\n");
            status = 1;
            goto clear_variables;
        }
        printf("\n");
    }

    if (make_user_directory(root_dir)) {
        status = 1;
        goto clear_variables;
    }

    if (storj_encrypt_write_auth(user_file, user_passphrase, bridge_opts.apikey, enc_access_str)) {
        status = 1;
        printf("Failed to write to disk\n");
        goto clear_variables;
    }

    printf("Successfully stored API key and encryption key to %s\n\n", user_file);

    clear_variables:
    free(user_input);
    free(user_file);
    free(root_dir);
    free(user_passphrase);
    free(new_enc_passphrase);
    free(enc_access_str);

    return status;
}

static void create_bucket_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    create_bucket_request_t *req = work_req->data;

    bool uplink_err = strcmp("", *STORJ_LAST_ERROR) != 0;
    if (req->status_code != 0 || uplink_err) {
        uplink_err ?
            printf("libuplink error: %s\n", *STORJ_LAST_ERROR) :
            printf("Unable to create bucket.");
        goto clean_variables;
    }

    if (req->bucket != NULL) {
        printf("ID: %s \tDecrypted: %s \tName: %s\n",
               req->bucket->id,
               req->bucket->decrypted ? "true" : "false",
               req->bucket->name);
    } else {
        printf("Failed to add bucket.\n");
    }

clean_variables:
    storj_free_create_bucket_request(req);
    free(work_req);
}

static int export_keys(char *host)
{
    int status = 0;
    char *user_file = NULL;
    char *root_dir = NULL;
    char *apikey = NULL;
    char *enc_access_str = NULL;
    char *user_passphrase = NULL;

    if (get_user_auth_location(host, &root_dir, &user_file)) {
        printf("Unable to determine user auth filepath.\n");
        status = 1;
        goto clear_variables;
    }

    if (access(user_file, F_OK) != -1) {
        user_passphrase = calloc(BUFSIZ, sizeof(char));
        printf("Unlock passphrase: ");
        get_password(user_passphrase, '*');
        printf("\n\n");

        if (storj_decrypt_read_auth(user_file, user_passphrase, &apikey, &enc_access_str)) {
            printf("Unable to read user file.\n");
            status = 1;
            goto clear_variables;
        }

        printf("Passphrase:\t%s\nEncryption key:\t%s\n", apikey, enc_access_str);
    }

clear_variables:
    if (apikey) {
        free(apikey);
    }
    if (enc_access_str) {
        free(enc_access_str);
    }
    if (root_dir) {
        free(root_dir);
    }
    if (user_file) {
        free(user_file);
    }
    if (user_passphrase) {
        free(user_passphrase);
    }
    return status;
}

int main(int argc, char **argv)
{
    int status = 0;
    char temp_buff[256] = {};

    // NB: seed pseudo-RNG with timestamp
    srand(time(NULL));

    static struct option cmd_options[] = {
        {"url", required_argument,  0, 'u'},
        {"version", no_argument,  0, 'v'},
        {"proxy", required_argument,  0, 'p'},
        {"log", required_argument,  0, 'l'},
        {"debug", no_argument,  0, 'd'},
        {"help", no_argument,  0, 'h'},
        {"recursive", required_argument,  0, 'r'},
        {0, 0, 0, 0}
    };

    int index = 0;

    // The default is usually 4 threads, we want to increase to the
    // locally set default value.
#ifdef _WIN32
    if (!getenv("UV_THREADPOOL_SIZE")) {
        _putenv_s("UV_THREADPOOL_SIZE", STORJ_THREADPOOL_SIZE);
    }
#else
    setenv("UV_THREADPOOL_SIZE", STORJ_THREADPOOL_SIZE, 0);
#endif

    char *storj_bridge = getenv("STORJ_BRIDGE");
    int c;
    int log_level = 0;
    char *local_file_path = NULL;

    char *proxy = getenv("STORJ_PROXY");

    while ((c = getopt_long_only(argc, argv, "hdl:p:vVu:r:R:",
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
            case 'R':
            case 'r':
                local_file_path = optarg;
                break;
            case 'h':
                printf(HELP_TEXT);
                exit(0);
                break;
            default:
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
        storj_bridge = "us-central-1.tardigrade.io:7777";
    }

    if (strcmp(command, "login") == 0) {
        printf("'login' is not a storj command. Did you mean 'import-keys'?\n\n");
        return 1;
    }

    if (strcmp(command, "import-keys") == 0) {
        user_options_t user_options = {storj_bridge, NULL, NULL, NULL};
        return import_keys(&user_options);
    }

    if (strcmp(command, "export-keys") == 0) {
        return export_keys(storj_bridge);
    }

    // initialize event loop and environment
    storj_env_t *env = NULL;

    storj_http_options_t http_options = {0};

    storj_log_options_t log_options = {
        .logger = json_logger,
        .level = log_level
    };

    char *apikey = NULL;
    char *enc_access_str = NULL;
    cli_api_t *cli_api = NULL;

    char *user_file = NULL;
    char *root_dir = NULL;
    if (get_user_auth_location(storj_bridge, &root_dir, &user_file)) {
        printf("Unable to determine user auth filepath.\n");
        return 1;
    }

    // We aren't using root dir so free it
    free(root_dir);

    // First, get auth from environment variables
    apikey = getenv("STORJ_API_KEY") ?
        strdup(getenv("STORJ_API_KEY")) : NULL;

    enc_access_str = getenv("STORJ_ENCRYPTION_KEY") ?
        strdup(getenv("STORJ_ENCRYPTION_KEY")) : NULL;

    char *user_passphrase_env = getenv("STORJ_KEYPASS");

    // Second, try to get from encrypted user file
    if ((!apikey || !enc_access_str) && access(user_file, F_OK) != -1) {

        char *user_passphrase = NULL;
        if (user_passphrase_env) {
            user_passphrase = calloc(strlen(user_passphrase_env) + 1, sizeof(char));
            if (!user_passphrase) {
                return 1;
            }
            strcpy(user_passphrase, user_passphrase_env);
        } else {
            user_passphrase = calloc(BUFSIZ, sizeof(char));
            if (!user_passphrase) {
                return 1;
            }
            printf("Unlock passphrase: ");
            get_password(user_passphrase, '*');
            printf("\n");
        }
        char *file_apikey = NULL;
        char *file_enc_access = NULL;
        if (storj_decrypt_read_auth(user_file, user_passphrase, &file_apikey,
                                    &file_enc_access)) {
            printf("Unable to read user file. Invalid keypass or path.\n");
            free(user_passphrase);
            free(user_file);
            free(file_apikey);
            free(file_enc_access);
            goto end_program;
        }
        free(user_passphrase);
        free(user_file);

        if (!apikey && file_apikey) {
            apikey = file_apikey;
        } else if (file_apikey) {
            free(file_apikey);
        }

        if (!enc_access_str && file_enc_access) {
            enc_access_str = file_enc_access;
        } else if (file_enc_access) {
            free(file_enc_access);
        }
    }

    // Third, ask for authentication
    if (!apikey) {
        apikey = calloc(BUFSIZ, sizeof(char));
        printf("Project API key: ");
        get_input(apikey);
        printf("\n");

        if (strlen(apikey) == 0) {
            // TODO: add link
            printf("Project API key required. See <link here>\n");
            status = 1;
            goto end_program;
        }
    }

    if (!enc_access_str) {
        printf("Encryption key: ");
        char *enc_access_input = malloc(BUFSIZ);
        if (enc_access_input == NULL) {
            return 1;
        }
        get_input(enc_access_input);
        int num_chars = strlen(enc_access_input);
        enc_access_str = calloc(num_chars + 1, sizeof(char));
        if (!enc_access_str) {
            return 1;
        }
        memcpy(enc_access_str, enc_access_input, num_chars);
        free(enc_access_input);
        printf("\n");
    }

    storj_bridge_options_t options = {
        .addr  = storj_bridge,
        .apikey = apikey,
    };

    storj_encrypt_options_t encrypt_options = {
        .encryption_key = enc_access_str
    };

    env = storj_init_env(&options, &encrypt_options,
                         &http_options, &log_options);
    if (!env) {
        status = 1;
        goto end_program;
    }

    cli_api = malloc(sizeof(cli_api_t));

    if (!cli_api) {
        status = 1;
        goto end_program;
    }
    memset(cli_api, 0x00, sizeof(*cli_api));

    cli_api->env = env;

    #ifdef debug_enable
    printf("command = %s; command_index = %d\n", command, command_index);
    printf("local_file_path (req arg_ = %s\n", local_file_path);
    for (int i = 0x00; i < argc; i++) {
        printf("argc = %d; argv[%d] = %s\n", argc, i, argv[i]);
    }

    for (int i = 0x00; i < (argc - command_index); i++) {
        printf("argc = %d; argv[command_index+%d] = %s\n", argc, i, argv[command_index + i]);
    }
    #endif

    if (strcmp(command, "download-file") == 0) {
        char *bucket_id = argv[command_index + 1];
        char *file_id = argv[command_index + 2];
        char *path = argv[command_index + 3];

        if (!bucket_id || !file_id || !path) {
            printf("Missing arguments: <bucket-id> <file-id> <path>\n");
            status = 1;
            goto end_program;
        }

        memcpy(cli_api->bucket_id, bucket_id, strlen(bucket_id));
        memcpy(cli_api->file_id, file_id, strlen(file_id));
        cli_api->dst_file = path;

        if (download_file(env, bucket_id, file_id, path, enc_access_str, cli_api)) {
            status = 1;
            goto end_program;
        }
    } else if (strcmp(command, "upload-file") == 0) {
        char *bucket_id = argv[command_index + 1];
        char *path = argv[command_index + 2];

        if (!bucket_id || !path) {
            printf("Missing arguments: <bucket-id> <path>\n");
            status = 1;
            goto end_program;
        }

        memcpy(cli_api->bucket_id, bucket_id, strlen(bucket_id));
        cli_api->dst_file = path;

        if (upload_file(env, bucket_id, path, cli_api)) {
            status = 1;
            goto end_program;
        }
    } else if (strcmp(command, "list-files") == 0) {
        char *bucket_id = argv[command_index + 1];

        if (!bucket_id) {
            printf("Missing first argument: <bucket-id>\n");
            status = 1;
            goto end_program;
        }

        // TODO: expose list options to user?
        storj_bridge_list_files(env, bucket_id, get_enc_access(cli_api), NULL,
                                cli_api, list_files_callback);
    } else if ((strcmp(command, "add-bucket") == 0) || (strcmp(command, "mkbkt") == 0x00)) {
        char *bucket_name = argv[command_index + 1];

        if (!bucket_name) {
            printf("Missing first argument: <bucket-name>\n");
            status = 1;
            goto end_program;
        }

        // TODO: expose bucket config options to user?
        // TODO: remove bucket config
        RedundancyScheme redundancy_scheme = {
                .share_size = 256,
                .required_shares = 4,
                .repair_shares = 6,
                .optimal_shares = 8,
                .total_shares = 10
        };
        BucketConfig bucket_cfg = {
                .redundancy_scheme = redundancy_scheme
        };
        storj_bridge_create_bucket(env, bucket_name, &bucket_cfg,
                                   NULL, create_bucket_callback);

    } else if (strcmp(command, "remove-bucket") == 0) {
        char *bucket_id = argv[command_index + 1];

        if (!bucket_id) {
            printf("Missing first argument: <bucket-id>\n");
            status = 1;
            goto end_program;
        }

        storj_bridge_delete_bucket(env, bucket_id, cli_api,
                                   delete_bucket_callback);

    } else if (strcmp(command, "remove-file") == 0) {
        char *bucket_id = argv[command_index + 1];
        char *file_id = argv[command_index + 2];

        if (!bucket_id || !file_id) {
            printf("Missing arguments, expected: <bucket-id> <file-id>\n");
            status = 1;
            goto end_program;
        }
        storj_bridge_delete_file(env, bucket_id, file_id, get_enc_access(cli_api),
                                 cli_api, delete_file_callback);

    } else if (strcmp(command, "list-buckets") == 0) {
        storj_bridge_get_buckets(env, NULL, get_buckets_callback);
    } else if (strcmp(command, "cp") == 0) {
        #define UPLOAD_CMD          0x00
        #define DOWNLOAD_CMD        0x01
        #define RECURSIVE_CMD       0x02
        #define NON_RECURSIVE_CMD   0x03

        int ret = 0x00;
        char *src_path = NULL; /* holds the local path */
        char *dst_path = NULL; /* holds the storj:// path */
        char *bucket_name = NULL;
        int cmd_type = 0x00; /* 0-> upload and 1 -> download */
        char modified_src_path[256] = {}; /* use this buffer to store the loca-file-path, if modified */
        memset(modified_src_path, 0x00, sizeof(modified_src_path));
        char *upload_file_path = modified_src_path;

        /* cp command wrt to upload-file */
        if (local_file_path == NULL) {/*  without -r[R] */
            /* hold the local path */
            src_path = argv[command_index + 0x01];

            /* Handle the dst argument (storj://<bucket-name>/ */
            dst_path = argv[argc - 0x01];

            cmd_type = NON_RECURSIVE_CMD;
        } else { /* with -r[R] */
            if ((strcmp(argv[1],"-r") == 0x00) || (strcmp(argv[1],"-R") == 0x00)) {
                src_path = local_file_path;

                /* Handle the dst argument (storj://<bucket-name>/ */
                dst_path = argv[argc - 0x01];

                cmd_type = RECURSIVE_CMD;
            } else {
                printf("[%s][%d] Invalid command option '%s'\n",
                       __FUNCTION__, __LINE__, argv[1]);
                goto end_program;
            }
        }

        if ((strcmp(src_path, argv[command_index]) == 0x00) ||
            (strcmp(dst_path, argv[command_index]) == 0x00) ||
            (strcmp(dst_path, src_path) == 0x00)) {
            printf("[%s][%d] Invalid command option '%s'\n",
                   __FUNCTION__, __LINE__, argv[1]);
            goto end_program;
        }

        /* check for upload or download command */
        char sub_str[] = "storj://";
        ret = strpos(dst_path, sub_str);

        if (ret == 0x00) { /* Handle upload command*/
            if (cmd_type == NON_RECURSIVE_CMD) {
                if (check_file_path(src_path) != CLI_VALID_DIR) {
                    local_file_path = src_path;

                    bucket_name = dst_path;
                } else {
                    printf("[%s][%d] Invalid command entry\n",
                           __FUNCTION__, __LINE__);
                    goto end_program;
                }
            } else if (cmd_type == RECURSIVE_CMD) {
                local_file_path = src_path;

                bucket_name = dst_path;
            } else {
                printf("[%s][%d] Invalid command entry \n", __FUNCTION__, __LINE__);
                goto end_program;
            }

            cmd_type = UPLOAD_CMD;
        } else if (ret == -1) { /* Handle download command*/
            ret = strpos(src_path, sub_str);

            if (ret == 0x00) {
                if ((cmd_type == NON_RECURSIVE_CMD) || (cmd_type == RECURSIVE_CMD)) {
                    local_file_path = dst_path;
                    bucket_name = src_path;

                    char *dst_file_name = NULL;
                    dst_file_name = (char *)get_filename_separator(local_file_path);

                    /* token[0]-> storj:; token[1]->bucket_name; token[2]->upload_file_name */
                    char *token[0x03];
                    memset(token, 0x00, sizeof(token));
                    int num_of_tokens = validate_cmd_tokenize(bucket_name, token);

                    /* set the bucket name from which file(s) to be downloaded */
                    cli_api->bucket_name = token[1];

                    /* initialize the local folder to copy the downloaded file into */
                    cli_api->file_path = local_file_path;

                    /* initialize the filename to be downloaded as */
                    cli_api->dst_file = dst_file_name;

                    if ((argc == 0x04) || (argc == 0x05)) { /* handle non recursive operations */
                        if ((token[2] == NULL) || (strcmp(token[2], "*") == 0x00)) {
                            if (check_file_path(local_file_path) == CLI_VALID_DIR) {
                                cli_download_files(cli_api);
                            } else {
                                printf("[%s][%d] Invalid '%s' dst directory !!!!!\n",
                                        __FUNCTION__, __LINE__, local_file_path);
                                goto end_program;
                            }
                        } else if (token[2] != NULL) {
                            /* set the file to be downloaded */
                            cli_api->file_name = token[2];

                            if ((check_file_path(local_file_path) == CLI_VALID_DIR) || (strcmp(dst_file_name, ".") == 0x00)) {
                                memset(temp_buff, 0x00, sizeof(temp_buff));
                                strcat(temp_buff, local_file_path);
                                strcat(temp_buff, "/");
                                strcat(temp_buff, token[2]);
                                cli_api->dst_file = temp_buff;
                            } else if (strlen(dst_file_name) > 0x00) {
                                cli_api->dst_file = local_file_path;
                            } else {
                                printf("[%s][%d] Invalid '%s' dst directory !!!!!\n",
                                        __FUNCTION__, __LINE__, local_file_path);
                                goto end_program;
                            }
                            printf("[%s][%d]file %s downloaded from bucketname = %s as file %s\n",
                                   __FUNCTION__, __LINE__, cli_api->file_name, cli_api->bucket_name, cli_api->dst_file);
                            cli_download_file(cli_api);
                        } else {
                            printf("[%s][%d] Invalid '%s' dst directory !!!!!\n",
                                    __FUNCTION__, __LINE__, local_file_path);
                            goto end_program;
                        }
                    } else {
                        /* more args then needed wrong command */
                        printf("[%s][%d] Valid dst filename missing !!!!!\n", __FUNCTION__, __LINE__);
                        goto end_program;
                    }
                } else {
                    printf("[%s][%d] Invalid command entry \n", __FUNCTION__, __LINE__);
                    goto end_program;
                }
            } else {
                printf("[%s][%d]Invalid Command Entry (%d) \n",
                       __FUNCTION__, __LINE__, ret);
                goto end_program;
            }
        } else {
            printf("[%s][%d]Invalid Command Entry (%d) \n",
                   __FUNCTION__, __LINE__, ret);
            goto end_program;
        }

        if (cmd_type == UPLOAD_CMD) {
            /* handling single file copy with -r[R]: ./storj cp -r /home/kishore/libstorj/src/xxx.y storj://testbucket/yyy.x */
            /* Handle the src argument */
            /* single file to copy, make sure the files exits */
            if ((argc == 0x05) && (check_file_path(local_file_path) == CLI_VALID_REGULAR_FILE)) {
                cli_api->file_name = local_file_path;

                /* Handle the dst argument (storj://<bucket-name>/<file-name> */
                /* token[0]-> storj:; token[1]->bucket_name; token[2]->upload_file_name */
                char *token[0x03];
                memset(token,0x00, sizeof(token));
                int num_of_tokens = validate_cmd_tokenize(bucket_name, token);

                if ((num_of_tokens == 0x02) || (num_of_tokens == 0x03)) {
                    char *dst_file_name = NULL;

                    cli_api->bucket_name = token[1];
                    dst_file_name = (char *)get_filename_separator(local_file_path);

                    if ((token[2] == NULL) || (strcmp(dst_file_name, token[2]) == 0x00) ||
                        (strcmp(token[2], ".") == 0x00)) {
                        /* use the src list buff as temp memory to hold the dst filename */
                        memset(cli_api->src_list, 0x00, sizeof(cli_api->src_list));
                        strcpy(cli_api->src_list, dst_file_name);
                        cli_api->dst_file = cli_api->src_list;
                    } else {
                        cli_api->dst_file = token[2];
                    }
                    cli_upload_file(cli_api);
                } else {
                    printf("[%s][%d] Valid dst filename missing !!!!!\n", __FUNCTION__, __LINE__);
                    goto end_program;
                }
            }
            else {
                /* directory is being used, store it in file_path */
                cli_api->file_path = local_file_path;

                /* Handle wild character options for files selection */
                if (check_file_path(local_file_path) != CLI_VALID_DIR) {
                    char pwd_path[256] = { };
                    memset(pwd_path, 0x00, sizeof(pwd_path));
                    char *upload_list_file = pwd_path;

                    /* create "/tmp/STORJ_upload_list_file.txt" upload files list based on the file path */
                    if ((upload_list_file = getenv("TMPDIR")) != NULL) {
                        if (upload_list_file[(strlen(upload_list_file) - 1)] == '/') {
                            strcat(upload_list_file, "STORJ_output_list.txt");
                        } else {
                            strcat(upload_list_file, "/STORJ_output_list.txt");
                        }

                        /* check the directory and create the path to upload list file */
                        memset(cli_api->src_list, 0x00, sizeof(cli_api->src_list));
                        memcpy(cli_api->src_list, upload_list_file, sizeof(pwd_path));
                        cli_api->dst_file = cli_api->src_list;
                    } else {
                        printf("[%s][%d] Upload list file generation error!!! \n",
                               __FUNCTION__, __LINE__);
                        goto end_program;
                    }

                    /* if local file path is a file, then just get the directory
                       from that */
                    char *ret = NULL;
                    ret = strrchr(local_file_path, '/');
                    memset(temp_buff, 0x00, sizeof(temp_buff));
                    memcpy(temp_buff, local_file_path, ((ret - local_file_path)+1));

                    FILE *file = NULL;
                    /* create the file and add the list of files to be uploaded */
                    if ((file = fopen(cli_api->src_list, "w")) != NULL) {
                        if ((strcmp(argv[1],"-r") == 0x00) || (strcmp(argv[1],"-R") == 0x00)) {
                            fprintf(file, "%s\n", local_file_path);
                        }

                        for (int i = 0x01; i < ((argc - command_index) - 1); i++) {
                            fprintf(file, "%s\n", argv[command_index + i]);
                        }
                    } else {
                        printf("[%s][%d] Invalid upload src path entered\n", __FUNCTION__, __LINE__);
                        goto end_program;
                    }
                    fclose(file);

                    cli_api->file_path = temp_buff;
                } else {
                    /* its a valid directory so let the list of files to be uploaded be handled in
                       verify upload file () */
                    cli_api->dst_file = NULL;

                    memcpy(upload_file_path, cli_api->file_path, strlen(cli_api->file_path));
                    if (upload_file_path[(strlen(upload_file_path) - 1)] != '/') {
                        strcat(upload_file_path, "/");
                        cli_api->file_path = upload_file_path;
                    }
                }

                /* token[0]-> storj:; token[1]->bucket_name; token[2]->upload_file_name */
                char *token[0x03];
                memset(token, 0x00, sizeof(token));
                int num_of_tokens = validate_cmd_tokenize(bucket_name, token);

                if ((num_of_tokens > 0x00) && ((num_of_tokens >= 0x02) || (num_of_tokens <= 0x03))) {
                    char *dst_file_name = NULL;

                    cli_api->bucket_name = token[1];

                    if ((token[2] == NULL) ||
                        (strcmp(token[2], ".") == 0x00)) {
                        cli_upload_files(cli_api);
                    } else {
                        printf("[%s][%d] storj://<bucket-name>; storj://<bucket-name>/ storj://<bucket-name>/. !!!!!\n", __FUNCTION__, __LINE__);
                        goto end_program;
                    }
                } else {
                    printf("[%s][%d] Valid dst filename missing !!!!!\n", __FUNCTION__, __LINE__);
                    goto end_program;
                }
            }
        }
    } else if (strcmp(command, "upload-files") == 0) {
        /* get the corresponding bucket id from the bucket name */
        cli_api->bucket_name = argv[command_index + 1];
        cli_api->file_path = argv[command_index + 2];
        cli_api->dst_file = NULL;

        if (!cli_api->bucket_name || !cli_api->file_name) {
            printf("Missing arguments: <bucket-name> <path>\n");
            status = 1;
            goto end_program;
        }

        cli_upload_files(cli_api);
    } else if (strcmp(command, "download-files") == 0) {
        /* get the corresponding bucket id from the bucket name */
        cli_api->bucket_name = argv[command_index + 1];
        cli_api->file_path = argv[command_index + 2];

        if (!cli_api->bucket_name || !cli_api->file_path) {
            printf("Missing arguments: <bucket-name> <path>\n");
            status = 1;
            goto end_program;
        }

        cli_download_files(cli_api);
    } else if (strcmp(command, "mkbkt") == 0x00) {
        char *bucket_name = argv[command_index + 1];

        if (!bucket_name) {
            printf("Missing first argument: <bucket-name>\n");
            status = 1;
            goto end_program;
        }

        // TODO: expose bucket config options to user?
        // TODO: remove bucket config
        RedundancyScheme redundancy_scheme = {
                .share_size = 256,
                .required_shares = 4,
                .repair_shares = 6,
                .optimal_shares = 8,
                .total_shares = 10
        };
        BucketConfig bucket_cfg = {
                .redundancy_scheme = redundancy_scheme
        };
        storj_bridge_create_bucket(env, bucket_name, &bucket_cfg,
                                   NULL, create_bucket_callback);
    } else if (strcmp(command, "rm") == 0) {
        cli_api->bucket_name = argv[command_index + 1];
        cli_api->file_name = argv[command_index + 2];

        if (cli_api->file_name != NULL) {
            if (!cli_api->bucket_name|| !cli_api->file_name) {
                printf("Missing arguments, expected: <bucket-name> <file-name>\n");
                status = 1;
                goto end_program;
            }

            cli_remove_file(cli_api);
        }
        else {
            cli_remove_bucket(cli_api);
        }
    } else if (strcmp(command, "ls") == 0x00) {
        if (argv[command_index + 1] != NULL) {
            /* bucket-name , used to list files */
            cli_api->bucket_name = argv[command_index + 1];

            cli_list_files(cli_api);
        }
        else {
            cli_list_buckets(cli_api);
        }
    } else if (strcmp(command, "get-bucket-id") == 0) {
        cli_api->bucket_name = argv[command_index + 1];
        cli_get_bucket_id(cli_api);
    } else {
        printf("'%s' is not a storj command. See 'storj --help'\n\n",
               command);
        status = 1;
        goto end_program;
    }

    // run all queued events
    if (uv_run(env->loop, UV_RUN_DEFAULT)) {
        uv_loop_close(env->loop);

        // cleanup
        storj_destroy_env(env);

        status = 1;
        goto end_program;
    }

end_program:
    if (env) {
        storj_destroy_env(env);
    }
    if (apikey) {
        free(apikey);
    }
    if (enc_access_str) {
        free(enc_access_str);
    }
    if (cli_api){
        free(cli_api);
    }

    return status;
}
