#include "storjtests.h"

void fail(char *msg)
{
    printf("\t" KRED "FAIL" RESET " %s\n", msg);
}

void pass(char *msg)
{
    printf("\t" KGRN "PASS" RESET " %s\n", msg);
}


int create_test_file(char *file) {
    FILE *fp;
    fp = fopen(file, "w+");
    
    if (fp == NULL) {
        printf(KRED "Could not create Sample file: %s\n" RESET, file);
        exit(0);
    }

    char *sample_text = "It's in that place where I put that thing that time";
    fputs(sample_text, fp);

    fclose(fp);
    return 0;
}

void check_bridge_get_info(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    struct json_object* value;
    int success = json_object_object_get_ex(req->response, "info", &value);
    assert(success == 1);
    pass("storj_bridge_get_info");
}

void check_get_buckets(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;
    assert(json_object_is_type(req->response, json_type_array) == 1);

    struct json_object *bucket = json_object_array_get_idx(req->response, 0);
    struct json_object* value;
    int success = json_object_object_get_ex(bucket, "id", &value);
    assert(success == 1);
    pass("storj_bridge_get_buckets");
}

void check_create_bucket(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    struct json_object* value;
    int success = json_object_object_get_ex(req->response, "name", &value);
    assert(success == 1);
    assert(json_object_is_type(value, json_type_string) == 1);

    const char* name = json_object_get_string(value);
    assert(strcmp(name, "backups") == 0);
    pass("storj_bridge_create_bucket");
}

void check_delete_bucket(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;
    assert(req->response == NULL);
    assert(req->status_code == 200);

    pass("storj_bridge_delete_bucket");
}

void check_list_files(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    struct json_object *file = json_object_array_get_idx(req->response, 0);
    struct json_object *value;
    int success = json_object_object_get_ex(file, "id", &value);
    assert(success == 1);
    assert(json_object_is_type(value, json_type_string) == 1);

    const char* id = json_object_get_string(value);
    assert(strcmp(id, "f18b5ca437b1ca3daa14969f") == 0);

    pass("storj_bridge_list_files");
}

void check_bucket_tokens(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    struct json_object *value;
    int success = json_object_object_get_ex(req->response, "token", &value);
    assert(success == 1);
    assert(json_object_is_type(value, json_type_string) == 1);

    const char* token = json_object_get_string(value);

    char *t = "a264e12611ad93b1777e82065f86cfcf088967dba2f15559cea5e140d5339a0e";

    assert(strcmp(token, t) == 0);

    pass("storj_bridge_create_bucket_token");
}

void check_delete_file(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;
    assert(req->response == NULL);
    assert(req->status_code == 200);

    pass("storj_bridge_delete_file");
}

void check_create_frame(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    struct json_object *value;
    int success = json_object_object_get_ex(req->response, "id", &value);
    assert(success == 1);
    assert(json_object_is_type(value, json_type_string) == 1);

    const char* id = json_object_get_string(value);

    assert(strcmp(id, "d6367831f7f1b117ffdd0015") == 0);
    pass("storj_bridge_create_frame");
}

void check_get_frames(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    struct json_object *file = json_object_array_get_idx(req->response, 0);
    struct json_object *value;
    int success = json_object_object_get_ex(file, "id", &value);
    assert(success == 1);
    assert(json_object_is_type(value, json_type_string) == 1);

    const char* id = json_object_get_string(value);
    assert(strcmp(id, "52b8cc8dfd47bb057d8c8a17") == 0);

    pass("storj_bridge_get_frames");
}

void check_get_frame(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    struct json_object *value;
    int success = json_object_object_get_ex(req->response, "id", &value);
    assert(success == 1);
    assert(json_object_is_type(value, json_type_string) == 1);

    const char* id = json_object_get_string(value);

    assert(strcmp(id, "192f90792f42875a7533340b") == 0);
    pass("storj_bridge_get_frame");
}

void check_delete_frame(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;
    assert(req->response == NULL);
    assert(req->status_code == 200);

    pass("storj_bridge_delete_frame");
}

void check_file_info(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    struct json_object *value;
    int success = json_object_object_get_ex(req->response, "mimetype", &value);
    assert(success == 1);
    assert(json_object_is_type(value, json_type_string) == 1);

    const char* mimetype = json_object_get_string(value);

    assert(strcmp(mimetype, "video/ogg") == 0);
    pass("storj_bridge_get_file_info");
}

int test_api()
{

    // Make sure we have a tmp folder
    char *folder = getenv("TMPDIR");

    if (folder == 0) {
        printf("You need to set $TMPDIR before running.\n");
        exit(1);
    }
    char *file = strcat(folder, "samplefile.txt");
    create_test_file(file);

    // setup bridge options to point to mock server
    storj_bridge_options_t options = {
        .proto = "http",
        .host  = "localhost",
        .port  = 8091,
        .user  = "testuser@storj.io",
        .pass  = "dce18e67025a8fd68cab186e196a9f8bcca6c9e4a7ad0be8a6f5e48f3abd1b04"
    };

    // initialize event loop and environment
    storj_env_t *env = storj_init_env(&options);
    assert(env != NULL);

    int status;

    // get general api info
    status = storj_bridge_get_info(env, check_bridge_get_info);
    assert(status == 0);

    // get buckets
    status = storj_bridge_get_buckets(env, check_get_buckets);
    assert(status == 0);

    // create a new bucket with a name
    status = storj_bridge_create_bucket(env, "backups", check_create_bucket);
    assert(status == 0);

    char *bucket_id = "368be0816766b28fd5f43af5ba0fc54ab1be516e";

    // delete a bucket
    // TODO check for successful status code, response has object
    status = storj_bridge_delete_bucket(env, bucket_id, check_delete_bucket);
    assert(status == 0);

    // list files in a bucket
    status = storj_bridge_list_files(env, bucket_id, check_list_files);
    assert(status == 0);

    // create bucket tokens
    status = storj_bridge_create_bucket_token(env,
                                              bucket_id,
                                              BUCKET_PUSH,
                                              check_bucket_tokens);
    assert(status == 0);

    char *file_id = "998960317b6725a3f8080c2b26875b0d8fe5731c";

    // delete a file in a bucket
    status = storj_bridge_delete_file(env,
                                      bucket_id,
                                      file_id,
                                      check_delete_file);
    assert(status == 0);

    // create a file frame
    status = storj_bridge_create_frame(env, check_create_frame);
    assert(status == 0);

    // get frames
    status = storj_bridge_get_frames(env, check_get_frames);
    assert(status == 0);

    char *frame_id = "d4af71ab00e15b0c1a7b6ab2";

    // get frame
    status = storj_bridge_get_frame(env, frame_id, check_get_frame);
    assert(status == 0);

    // delete frame
    status = storj_bridge_delete_frame(env, frame_id, check_delete_frame);
    assert(status == 0);

    // TODO add shard to frame

    // get file information
    status = storj_bridge_get_file_info(env, bucket_id,
                                        file_id, check_file_info);
    assert(status == 0);

    // upload file
    storj_upload_opts_t upload_opts = {
        .file_concurrency = 1,
        .shard_concurrency  = 3,
        .redundancy  = 1,
        .bucket_id  = "368be0816766b28fd5f43af5ba0fc54ab1be516e",
        .file_path  = file,
        .key_pass = "password"
    };

    status = storj_bridge_store_file(env, &upload_opts);
    assert(status == 0);

    // run all queued events
    if (uv_run(env->loop, UV_RUN_DEFAULT)) {
        // Error
    }

    // shutdown
    status = uv_loop_close(env->loop);
    if (status == UV_EBUSY) {
        // Error
    }

    return OK;
}


int test_mnemonic_check()
{
    static const char *vectors_ok[] = {
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge",
        "renew stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
        "dignity pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
        "afford alter spike radar gate glance object seek swamp infant panel yellow",
        "indicate race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
        "clutch control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
        "turtle front uncle idea crush write shrug there lottery flower risk shell",
        "kiss carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
        "exile ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
        "board flee heavy tunnel powder denial science ski answer betray cargo cat",
        "board blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
        "beyond stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
        0,
    };
    static const char *vectors_fail[] = {
        "above abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "above winner thank year wave sausage worth useful legal winner thank yellow",
        "above advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "above zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "above abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "above winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        "above advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        "above zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        "above abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "above winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "above advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "above zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "above better achieve collect unaware mountain thought cargo oxygen act hood bridge",
        "above stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
        "above pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
        "above alter spike radar gate glance object seek swamp infant panel yellow",
        "above race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
        "above control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
        "above front uncle idea crush write shrug there lottery flower risk shell",
        "above carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
        "above ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
        "above flee heavy tunnel powder denial science ski answer betray cargo cat",
        "above blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
        "above stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "winner thank year wave sausage worth useful legal winner thank yellow",
        "advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        "advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "better achieve collect unaware mountain thought cargo oxygen act hood bridge",
        "stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
        "pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
        "alter spike radar gate glance object seek swamp infant panel yellow",
        "race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
        "control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
        "front uncle idea crush write shrug there lottery flower risk shell",
        "carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
        "ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
        "flee heavy tunnel powder denial science ski answer betray cargo cat",
        "blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
        "stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
        0,
    };

    const char **m;
    int r;
    m = vectors_ok;
    while (*m) {
        r = mnemonic_check(*m);
        assert(r == 1);
        m++;
    }
    m = vectors_fail;
    while (*m) {
        r = mnemonic_check(*m);
        assert(r == 0);
        m++;
    }

    pass("mnemonic_check");

    return OK;
}


int test_mnemonic_generate()
{
    int status;
    int stren = 128;
    char *mnemonic = calloc(250, sizeof(char));
    mnemonic_generate(stren, &mnemonic);
    status = mnemonic_check(mnemonic);

    if (status != 1) {
        fail("test_mnemonic_generate");
        printf("\t\texpected mnemonic check: %i\n", 0);
        printf("\t\tactual mnemonic check:   %i\n", status);
        free(mnemonic);
        return ERROR;
    }
    free(mnemonic);

    pass("test_mnemonic_check");

    return OK;
}

int test_generate_seed()
{
    char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    char *seed = calloc(128, sizeof(char));
    char *expected_seed = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

    mnemonic_to_seed(mnemonic, "", &seed);
    seed[128] = '\0';

    int check = memcmp(seed, expected_seed, 128);
    if (check != 0) {
        fail("test_generate_seed");
        printf("\t\texpected seed: %s\n", expected_seed);
        printf("\t\tactual seed:   %s\n", seed);

        free(seed);
        return ERROR;
    }

    free(seed);
    pass("test_generate_seed");

    return OK;
}

int test_generate_bucket_key()
{
    char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    char *bucket_id = "0123456789ab0123456789ab";
    char *bucket_key = calloc(64, sizeof(char));
    char *expected_bucket_key = "b2464469e364834ad21e24c64f637c39083af5067693605c84e259447644f6f6";

    generate_bucket_key(mnemonic, bucket_id, &bucket_key);
    bucket_key[64] = '\0';

    int check = strcmp(expected_bucket_key, bucket_key);
    if (check != 0) {
        fail("test_generate_bucket_key");
        printf("\t\texpected bucket_key: %s\n", expected_bucket_key);
        printf("\t\tactual bucket_key:   %s\n", bucket_key);

        free(bucket_key);
        return ERROR;
    }

    free(bucket_key);
    pass("test_generate_bucket_key");

    return OK;
}

int test_generate_file_key()
{
    char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    char *bucket_id = "0123456789ab0123456789ab";
    char *file_name = "samplefile.txt";
    char *file_id = calloc(24, sizeof(char));
    char *file_key = calloc(64, sizeof(char));
    char *expected_file_key = "fe5fe4dcc5cb094666957d135341283d1af766cfe3174b75e15935ef5387c533";

    calculate_file_id(bucket_id, file_name, &file_id);
    file_id[FILE_ID_SIZE] = '\0';
    generate_file_key(mnemonic, bucket_id, file_id, &file_key);
    file_key[64] = '\0';

    int check = strcmp(expected_file_key, file_key);
    if (check != 0) {
        fail("test_generate_file_key");
        printf("\t\texpected file_key: %s\n", expected_file_key);
        printf("\t\tactual file_key:   %s\n", file_key);

        free(file_key);
        free(file_id);
        return ERROR;
    }

    free(file_key);
    free(file_id);
    pass("test_generate_file_key");

    return OK;
}

int test_calculate_file_id()
{
    char *bucket_id = "0123456789ab0123456789ab";
    char *file_name = "samplefile.txt";
    char *file_id = calloc(24, sizeof(char));
    char *expected_file_id = "852b6c9a0ba914a31e301a4b";

    calculate_file_id(bucket_id, file_name, &file_id);

    int check = strcmp(file_id, expected_file_id);
    if (check != 0) {
        fail("test_calculate_file_id");
        printf("\t\texpected file_id: %s\n", expected_file_id);
        printf("\t\tactual file_id:   %s\n", file_id);

        free(file_id);
        return ERROR;
    }

    pass("test_calculate_file_id");

    free(file_id);

    return OK;
}


// Test Server
struct MHD_Daemon *start_test_server()
{
    // spin up test server
    return MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION,
                            8091,
                            NULL,
                            NULL,
                            &mock_bridge_server,
                            NULL,
                            MHD_OPTION_END);
}




int main(void)
{
    // spin up test server
    struct MHD_Daemon *d = start_test_server();
    if (d == NULL) {
        printf("Could not start test server.\n");
        return 0;
    };

    int tests_ran = 0;

    int status = 0;
    printf("Test Suite: API\n");
    status -= test_api();
    ++tests_ran;
    printf("\n");

    // printf("Test Suite: BIP39\n");
    // status -= test_mnemonic_check();
    // ++tests_ran;
    // status -= test_mnemonic_generate();
    // ++tests_ran;
    // status -= test_generate_seed();
    // ++tests_ran;
    // printf("\n");

    // printf("Test Suite: Crypto\n");
    // status -= test_calculate_file_id();
    // ++tests_ran;
    // status -= test_generate_bucket_key();
    // ++tests_ran;
    // status -= test_generate_file_key();
    // ++tests_ran;
    // printf("\n");

    printf(KGRN "\nPASSED: %i\n" RESET, abs(status));
    printf(KRED "FAILED: %i\n" RESET, (tests_ran + status) );
    printf("TOTAL: %i\n", (tests_ran));


    // Shutdown test server
    MHD_stop_daemon(d);

    return 0;
}
