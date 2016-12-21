#include "storj.h"

#define HELP_TEXT "usage: storj <command> [<args>]\n\n"                 \
    "These are common Storj commands for various situations:\n\n"       \
    "working with buckets and files\n"                                  \
    "  list-buckets\n"                                                  \
    "  list-files <bucket-id>\n"                                        \
    "  add-bucket <name> \n\n"                                          \
    "downloading and uploading files\n"                                 \
    "  upload-file <bucket-id> <path>\n"                                \
    "  download-file <bucket-id> <file-id> <path>\n\n"                  \

int main(int argc, char **argv)
{

    char *command = argv[1];
    if (!command) {
        command = "help";
    }

    if(strcmp(command, "download-file") == 0) {
        // TODO
    } else {
        printf(HELP_TEXT);
        return 1;
    }

    return 0;
}
