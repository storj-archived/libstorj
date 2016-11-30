#include "storjtests.h"

void req_callback(uv_work_t *work_req, int status)
{
    json_request_t *req = work_req->data;
    printf("%s\n\n\n", json_object_to_json_string(req->response));
}

int create_test_file(char *file) {
    FILE *fp;
    fp = fopen(file, "w+");
    fprintf(fp, "Sample file...\n");
    fclose(fp);

    return 0;
}

START_TEST(api)
{

    // Make sure we have a tmp folder
    char const *folder = getenv("TMPDIR");

    if (folder == 0) {
        printf("You need to set $TMPDIR before running.");
        exit(0);
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

    // setup bridge options to point to mock server
    storj_upload_opts_t upload_opts = {
        .file_concurrency = 1,
        .shard_concurrency  = 3,
        .redundancy  = 1,
        .bucket_id  = "368be0816766b28fd5f43af5ba0fc54ab1be516e",
        .file_path  = file,
        .key_pass = "password"
    };

    // initialize event loop and environment
    storj_env_t *env = storj_init_env(&options);
    assert(env != NULL);


    int status;

    // get general api info
    status = storj_bridge_get_info(env, req_callback);
    assert(status == 0);

    // get buckets
    status = storj_bridge_get_buckets(env, req_callback);
    assert(status == 0);

    // create a new bucket with a name
    status = storj_bridge_create_bucket(env, "backups", req_callback);
    assert(status == 0);

    char *bucket_id = "368be0816766b28fd5f43af5ba0fc54ab1be516e";

    // delete a bucket
    // TODO check for successful status code, response has object
    status = storj_bridge_delete_bucket(env, bucket_id, req_callback);
    assert(status == 0);

    // list files in a bucket
    status = storj_bridge_list_files(env, bucket_id, req_callback);
    assert(status == 0);

    // create bucket tokens
    status = storj_bridge_create_bucket_token(env,
                                              bucket_id,
                                              BUCKET_PUSH,
                                              req_callback);
    assert(status == 0);

    char *file_id = "998960317b6725a3f8080c2b26875b0d8fe5731c";

    // delete a file in a bucket
    status = storj_bridge_delete_file(env,
                                      bucket_id,
                                      file_id,
                                      req_callback);
    assert(status == 0);

    // create a file frame
    status = storj_bridge_create_frame(env, req_callback);
    assert(status == 0);

    // get frames
    status = storj_bridge_get_frames(env, req_callback);
    assert(status == 0);

    char *frame_id = "d4af71ab00e15b0c1a7b6ab2";

    // get frame
    status = storj_bridge_get_frame(env, frame_id, req_callback);
    assert(status == 0);

    // delete frame
    status = storj_bridge_delete_frame(env, frame_id, req_callback);
    assert(status == 0);

    // TODO add shard to frame

    // get file information
    status = storj_bridge_get_file_info(env, bucket_id, file_id, req_callback);
    assert(status == 0);

    // upload file
    status = storj_bridge_store_file(env, &upload_opts);
    assert(status == 0);

    int stren = 128;
    char *mnemonic = calloc(250, sizeof(char));
    status = mnemonic_generate(stren, &mnemonic);
    printf("\nmnemonic: %s\n", mnemonic);
    free(mnemonic);

    // run all queued events
    if (uv_run(env->loop, UV_RUN_DEFAULT)) {
        // Error
    }

    // shutdown
    status = uv_loop_close(env->loop);
    if (status == UV_EBUSY) {
        // Error
    }
}
END_TEST

START_TEST(test_mnemonic_check)
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
		ck_assert_int_eq(r, 1);
		m++;
	}
	m = vectors_fail;
	while (*m) {
		r = mnemonic_check(*m);
		ck_assert_int_eq(r, 0);
		m++;
	}
}
END_TEST

START_TEST(test_mnemonic_generate)
{
    int status;
    int stren = 128;
    char *mnemonic = calloc(250, sizeof(char));
    status = mnemonic_generate(stren, &mnemonic);
    ck_assert_int_ne(0, status);
    status = mnemonic_check(mnemonic);
    ck_assert_int_eq(1, status);
    free(mnemonic);
}
END_TEST

// define test suite and cases
Suite *test_suite(void)
{
	Suite *s = suite_create("libstorj-c");
	TCase *tc;

	tc = tcase_create("Bip39 Integration");
    tcase_add_test(tc, test_mnemonic_check);
	tcase_add_test(tc, test_mnemonic_generate);
	suite_add_tcase(s, tc);

    tc = tcase_create("API tests");
    tcase_add_test(tc, api);
    suite_add_tcase(s, tc);

	return s;
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

    // Prepare tests
    int number_failed;
	Suite *s = test_suite();
	SRunner *sr = srunner_create(s);

    // Run tests
	srunner_run_all(sr, CK_VERBOSE);

    // Check failures
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	if (number_failed == 0) {
		printf("PASSED ALL TESTS\n");
	}

    // Shutdown test server
    MHD_stop_daemon(d);
	return number_failed;
}
