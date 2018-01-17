#include "storjapi_callback.h"

static void delete_file_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    storj_api_t *storj_api = req->handle;
    storj_api->last_cmd_req = storj_api->curr_cmd_req;
    storj_api->rcvd_cmd_resp = "get-bucket-id-resp";

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
    storj_api->rcvd_cmd_resp = "get-bucket-id-resp";

    if (req->status_code == 200 || req->status_code == 204) {
        printf("Bucket was successfully removed.\n");
    } else if (req->status_code == 401) {
        printf("Invalid user credentials.\n");
        goto cleanup;
    } else {
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

    if (req->status_code == 401) {
       printf("Invalid user credentials.\n");
       goto cleanup;
    } else if (req->status_code != 200 && req->status_code != 304) {
        printf("Request failed with status code: %i\n", req->status_code);
        goto cleanup;
    } else if (req->total_buckets == 0) {
        printf("No buckets.\n");
        goto cleanup;
    }

    for (int i = 0; i < req->total_buckets; i++)
    {
        storj_bucket_meta_t *bucket = &req->buckets[i];

        if(strcmp(storj_api->bucket_name, bucket->name) == 0x00)
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
            if (i >= (req->total_buckets -1))
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

    if (req->status_code == 404) {
        printf("Bucket id [%s] does not exist\n", req->bucket_id);
        goto cleanup;
    } else if (req->status_code == 400) {
        printf("Bucket id [%s] is invalid\n", req->bucket_id);
        goto cleanup;
    } else if (req->status_code == 401) {
        printf("Invalid user credentials.\n");
        goto cleanup;
    } else if (req->status_code != 200) {
        printf("Request failed with status code: %i\n", req->status_code);
    }

    if (req->total_files == 0) {
        printf("No files for bucket.\n");
        goto cleanup;
    }

    for (int i = 0; i < req->total_files; i++) 
    {
        storj_file_meta_t *file = &req->files[i];

        if ((storj_api->file_name != NULL) && 
            (strcmp(storj_api->file_name,file->filename)) == 0x00)
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
    }

    queue_next_cmd_req(storj_api);

cleanup:

    storj_free_list_files_request(req);
    free(work_req);
}

void queue_next_cmd_req(storj_api_t *storj_api)
{
    void *handle = storj_api->handle;

    if (strcmp(storj_api->excp_cmd_resp, storj_api->rcvd_cmd_resp) == 0x00)
    {
        printf("[%s][%d]expt resp = %s; rcvd resp = %s \n",
               __FUNCTION__, __LINE__,
                storj_api->excp_cmd_resp, storj_api->rcvd_cmd_resp );
        printf("[%s][%d]last cmd = %s; cur cmd = %s; next cmd = %s\n",
               __FUNCTION__, __LINE__, storj_api->last_cmd_req, 
               storj_api->curr_cmd_req, storj_api->next_cmd_req);

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
            storj_api->excp_cmd_resp = "remove-bucekt-resp";
            storj_bridge_delete_bucket(storj_api->env, storj_api->bucket_id, 
                                       storj_api, delete_bucket_callback);
        }
        else if ((storj_api->next_cmd_req != NULL) && 
                 (strcmp(storj_api->next_cmd_req, "remove-file-req") == 0x00))
        {
            printf("I am here\n");
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
    }

#if 0
    if (((strcmp("list-files"  , storj_api->curr_cmd_req) == 0x00)||
        ((strcmp("download-file" , storj_api->curr_cmd_req) == 0x00))) &&
        ((strcmp("list-files-1", storj_api->next_cmd_req) == 0x00)||
         (strcmp("download-file-1", storj_api->next_cmd_req)==0x00)))
    {
        if(strcmp("list-files-1" , storj_api->next_cmd_req) == 0x00)
        {
            storj_bridge_list_files(storj_api->env, storj_api->bucket_id, storj_api, list_files_callback);
        }

        if(strcmp("download-file-1" , storj_api->next_cmd_req) == 0x00)
        {
            //FILE *file = fopen("/home/kishore/libstorj/src/dwnld_list.txt", "r");
            FILE *file = fopen("dwnld_list.txt", "r");
            if (file != NULL)
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
                    temp = line[i];
                    i++;
                    if (i >= storj_api->curr_up_file)
                    {
                        break;
                    }
                }

                /* start tokenizing */
                token[0] = strtok(temp, ":");
                while (token[tk_idx] != NULL)
                {
                    tk_idx++;
                    token[tk_idx] = strtok(NULL, ":");
                }

                if(storj_api->curr_up_file <= storj_api->total_files)
                {
                    storj_api->file_id = token[0];
                    strcpy(temp_path, storj_api->file_path);
                    strcat(temp_path, token[1]);
                    fprintf(stdout,"*****[%d:%d] downloading file: %s *****\n",
                            storj_api->curr_up_file, storj_api->total_files, temp_path);
                    storj_api->curr_up_file++;
                    download_file(storj_api->env, storj_api->bucket_id, storj_api->file_id, temp_path, storj_api);
                }
                else
                {
                    fprintf(stdout,"***** done downloading files  *****\n");
                    fclose(file);
                    exit(0);
                }
            }
            else
            {
                download_file(storj_api->env, storj_api->bucket_id, storj_api->file_id, storj_api->file_path,storj_api);
            }

        }
    }
    else if ((strcmp("upload-file"  , storj_api->curr_cmd_req) == 0x00) &&
             (strcmp("upload-file-1", storj_api->next_cmd_req) == 0x00))
    {
        FILE *file = fopen(storj_api->file_name, "r");
        if (file != NULL)
        {
            char line[256][256];
            char *temp;
            int i = 0x00;
            memset(line, 0x00, sizeof(line));
            while((fgets(line[i],sizeof(line), file)!= NULL)) /* read a line from a file */
            {
                temp = strrchr(line[i], '\n');
                if(temp) *temp = '\0';
                storj_api->file_path = line[i];
                i++;
                printf("[%s][%d] [index = %d] target file name = %s\n", __FUNCTION__, __LINE__, i, line[i-1]);
                if(i >= storj_api->curr_up_file)
                  break;
            }
            if(storj_api->curr_up_file <= storj_api->total_files)
            {
                fprintf(stdout,"*****uploading file: %s *****\n",line[i-1]); //print the file contents on stdout.
                upload_file(storj_api->env, storj_api->bucket_id, storj_api->file_path, storj_api);
                storj_api->curr_up_file++;
            }
            else
            {
                fprintf(stdout,"***** done uploading files  *****\n");
                fclose(file);
                exit(0);
            }
        }
        else
        {
            /* handle single file upload from the command line */
            upload_file(storj_api->env, storj_api->bucket_id, storj_api->file_path, storj_api);
        }
    }
    #endif
}
