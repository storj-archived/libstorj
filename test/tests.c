#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "../src/storj.h"

int main(void)
{

    json_object *obj = storj_bridge_get_info();

    printf("%s\n", json_object_to_json_string(obj));

    return 0;

}
