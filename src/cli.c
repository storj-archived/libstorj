#include "storj.h"

int main(int argc, char **argv)
{

    char *command = argv[1];
    if (!command) {
        command = "help";
    }

    if(strcmp(command, "download-file") == 0) {
        // TODO
    } else {
        printf("usage: storj download-file <bucket-id> <file-id> <path>\n");
        return 1;
    }

    return 0;
}
