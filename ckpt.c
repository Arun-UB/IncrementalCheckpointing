/*
 * ckpt.c
 *
 *  Created on: Jan 15, 2016
 *      Author: Praveen
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>
#include <git2.h>
#include <fts.h>
#include <curl/curl.h>
#include <jansson.h>
#include <glob.h>

#define IS_MEM_READABLE(flags) (flags & 0x80)
#define IS_MEM_WRITABLE(flags) (flags & 0x40)
#define IS_MEM_EXECUTABLE(flags) (flags & 0x20)
#define IS_MEM_PRIVATE(flags) (flags & 0x10)
#define IS_STACK_MEMORY(flags) (flags & 0x08)
#define IS_CPU_CONTEXT(flags) (flags & 0x04)
#define SET_MEM_READABLE(flags) (flags |= 0x80)
#define SET_MEM_WRITABLE(flags) (flags |= 0x40)
#define SET_MEM_EXECUTABLE(flags) (flags |= 0x20)
#define SET_MEM_PRIVATE(flags) (flags |= 0x10)
#define SET_STACK_MEMORY(flags) (flags |= 0x08)
#define SET_CPU_CONTEXT(flags) (flags |= 0x04)

#define MAX_STRING_LEN 128

typedef struct {
	long start_addr;
	long end_addr;
	uint8_t mem_flags;
} meta_data_t;

char web_url[256];
#define CHECKPOINT_DIR_PATH "/tmp"

void fetch_meta_data(char* buffer, meta_data_t* meta_data) {
	char tmp_buffer[1024], *addr_range = NULL, *flags = NULL;
	int index = 0;

	strncpy(tmp_buffer, buffer, 1024);
	addr_range = strtok(tmp_buffer, " ");
	flags = strtok(NULL, " ");

	meta_data->start_addr = strtol(strtok(addr_range, "-"), NULL, 16);
	meta_data->end_addr = strtol(strtok(NULL, "-"), NULL, 16);

	while (index < strlen(flags)) {
		switch (flags[index++]) {
		case 'r':
			SET_MEM_READABLE(meta_data->mem_flags);
			break;
		case 'w':
			SET_MEM_WRITABLE(meta_data->mem_flags);
			break;
		case 'x':
			SET_MEM_EXECUTABLE(meta_data->mem_flags);
			break;
		case 'p':
			SET_MEM_PRIVATE(meta_data->mem_flags);
			break;
		case '-':
			break;
		default:
			printf("\nERROR: Unknown Memory Protection Flag \n");
			break;
		}
	}

	if (strstr(buffer, "stack") != NULL)
		SET_STACK_MEMORY(meta_data->mem_flags);

}

int Write(int fd, const void* buffer, int len) {
	int ret = -1;
	while ((ret = write(fd, buffer, len)) != len) {
		if (ret < 0) {
			printf("\nERROR: Failed to write to checkpoint image: %d\n", ret);
			return ret;
		}
		len -= ret;
		buffer += ret;
	}
	return ret;
}

static void check_error(int error_code, const char *action) {
	const git_error *error = giterr_last();
	if (!error_code)
		return;

	printf("Error %d %s - %s\n", error_code, action,
			(error && error->message) ? error->message : "???");

	return;
}

size_t function_pt(void *ptr, size_t size, size_t nmemb, void *stream) {
	strncat(stream, ptr, nmemb);
	return size * nmemb;
}

int create_remote_repo(char* repo_name, char* web_url) {
	CURL *curl= NULL;
	CURLcode res;
	char buffer[1024] = { 0 };
	char response[4096] = { 0 };
	int ret = 0;

	snprintf(buffer, 1024,
			"name=%s&private_token=JtjTzjkku3npH3tMRnx4&public=true",
			repo_name);
	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL,
				"http://ec2-54-152-38-69.compute-1.amazonaws.com/api/v3/projects");
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buffer);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) strlen(buffer));
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, function_pt);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

		// Perform the request, res will get the return code
		res = curl_easy_perform(curl);

		// Check for errors
		if (res != CURLE_OK) {
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
					curl_easy_strerror(res));
			ret = -1;
		}

		// always cleanup
		curl_easy_cleanup(curl);
	}

	if (strcmp(response, "")) {
		json_t *root= NULL, *data= NULL;
		json_error_t error;

		root = json_loads(response, 0, &error);

		if (!root) {
			fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
			return -1;
		}

		data = json_object_get(root, "web_url");
		if (!json_is_string(data)) {
			fprintf(stderr, "error: message is not a string\n");
			json_decref(root);
		} else {
			strcpy(web_url, json_string_value(data));
			json_decref(root);
		}
	}

	return ret;
}

void http_post_message(char* data, char* url) {

	CURL *curl= NULL;
	CURLcode res;
	char response[4096] = { 0 };

	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) strlen(data));
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, function_pt);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

		// Perform the request, res will get the return code
		res = curl_easy_perform(curl);

		// Check for errors
		if (res != CURLE_OK) {
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
					curl_easy_strerror(res));
		}

		// always cleanup
		curl_easy_cleanup(curl);
	}
}

void set_remote_url(git_repository* repo) {
	int ret = 0;

	ret = git_remote_set_pushurl(repo, "origin", web_url);
	check_error(ret, "git_remote_set_pushurl");

	ret = git_remote_set_url(repo, "origin", web_url);
	check_error(ret, "git_remote_set_url");
}

int cred_acquire_cb(git_cred** cred, const char* url,
		unsigned int allowed_types, void* payload) {
	return git_cred_userpass_plaintext_new(cred, "root", "Qwerty12");
}

int push_to_remote_repo(git_repository* repo) {
	git_remote *remote = { 0 };
	int ret;

	ret = git_remote_lookup(&remote, repo, "origin");
	check_error(ret, "git_remote_lookup");

	git_remote_callbacks cb = GIT_REMOTE_CALLBACKS_INIT;
	cb.credentials = (git_cred_acquire_cb) cred_acquire_cb;

	ret = git_remote_connect(remote, GIT_DIRECTION_PUSH, &cb, NULL);
	check_error(ret, "git_remote_connect");

	// add a push refspec
	ret = git_remote_add_push(repo, "origin",
			"refs/heads/master:refs/heads/master");
	check_error(ret, "git_remote_add_push");

	// configure options
	git_push_options options;
	ret = git_push_init_options(&options, GIT_PUSH_OPTIONS_VERSION);
	check_error(ret, "git_push_init_options");

	// do the push
	char* refs = "refs/heads/master";
	git_strarray refs_array = { &refs, 1 };
	ret = git_remote_upload(remote, &refs_array, &options);
	check_error(ret, "git_remote_upload");

	return 0;
}

static int dump_to_checkpoint_file(meta_data_t* meta_data, void* data, int len,
		char* output_file) {
	int out_fd;
	if ((out_fd = open(output_file,
	O_WRONLY | O_CREAT | O_TRUNC,
	S_IRWXU | S_IRGRP | S_IROTH)) == -1) {
		printf("\nERROR: Failed to open ckpt file: %d\n", errno);
		return errno;
	}

	if (Write(out_fd, (void *) meta_data, sizeof(meta_data_t)) < 0) {
		printf("\nERROR: Failed to write to ckpt file: %d\n", errno);
		return errno;
	}

	if (Write(out_fd, (void *) data, len) < 0) {
		printf("\nERROR: Failed to open ckpt file: %d\n", errno);
		return errno;
	}

	close(out_fd);
	return 0;

}

static void commit_changes(git_repository* repo) {
	int rc; /* return code for git_ functions */
	git_oid oid_tree= {.id= {0} }; /* the SHA1 for our tree in the commit */
	git_tree * tree_cmt= NULL; /* our tree in the commit */
	git_signature *author =NULL;
	git_oid oid_commit= {.id= {0} }; /* the SHA1 for our initial commit */
	git_index *index=NULL;
	char checkpoint_message[MAX_STRING_LEN] = { 0 };
	static int checkpoint_no = 0;

	rc = git_repository_index(&index, repo);
	check_error(rc, "Could not open repository index");

	rc = git_index_add_all(index, NULL, 0, NULL, NULL);
	check_error(rc, "Could not add index");

	// Write the index to disk.
	rc = git_index_write(index);
	check_error(rc, "Could not write index to disk");

	rc = git_index_write_tree(&oid_tree, index);
	check_error(rc, "could not write tree");

	git_signature_new((git_signature **) &author, "Praveen",
			"praveenkmurthy@gmail.com", time(NULL), 0);

	rc = git_tree_lookup(&tree_cmt, repo, &oid_tree);

	git_commit* parent_ptr = NULL;
	int parent_count = 0;

	if (checkpoint_no) {
		git_oid oid_parent_commit= {.id= {0} }; /* the SHA1 for last commit */

		/* resolve HEAD into a SHA1 */
		rc = git_reference_name_to_id(&oid_parent_commit, repo, "HEAD");
		check_error(rc, "Get Reference HEAD failed!!");

		rc = git_commit_lookup(&parent_ptr, repo, &oid_parent_commit);
		check_error(rc, "Commit Lookup failed");

		parent_count = 1;
		snprintf(checkpoint_message, MAX_STRING_LEN,
				"Incremental checkpoint %d", checkpoint_no);
		checkpoint_no++;
	} else {
		snprintf(checkpoint_message, MAX_STRING_LEN, "Initial checkpoint");
		checkpoint_no++;
	}

	rc = git_commit_create_v(&oid_commit, repo, "HEAD", author, author, /* same author and commiter */
	NULL, /* default UTF-8 encoding */
	checkpoint_message, tree_cmt, parent_count, parent_ptr);

	git_tree_free(tree_cmt);
}

void verify_checkpoint_dir(char* checkpoint_dir, git_repository * repo) {
	FILE* in_fd = NULL;
	struct stat st = { 0 };
	char buffer[1024] = { 0 };
	meta_data_t meta_data = { 0 };

	if ((in_fd = fopen("/proc/self/maps", "r")) == NULL) {
		printf("\nERROR: Failed to open /proc/self/maps: %s\n",
				strerror(errno));
		return;
	}

	while ((fgets(buffer, 1024, in_fd) > 0)) {
		if (strstr(buffer, "vsyscall") != NULL)
			goto LOOP;

		fetch_meta_data(buffer, &meta_data);

		if (!IS_MEM_READABLE(meta_data.mem_flags))
			goto LOOP;

		char file_path[128] = { 0 };
		snprintf(file_path, 128, "%s/%lx-%lx", checkpoint_dir,
				meta_data.start_addr, meta_data.end_addr);
		if (stat(file_path, &st) == -1) {
			printf("Error: File doesn't exist: %s\n", file_path);
			dump_to_checkpoint_file(&meta_data, (void*) meta_data.start_addr,
					(meta_data.end_addr - meta_data.start_addr), file_path);

			git_oid oid_blob= {.id= {0} } ;
			int error;

			error = git_blob_create_fromdisk(&oid_blob, repo, file_path);
			check_error(error, "creating blob");

			commit_changes(repo);
			verify_checkpoint_dir(checkpoint_dir, repo);
		}

		LOOP: memset(&meta_data, 0, sizeof(meta_data));
		memset(buffer, 0, 1024);
	}
}

int get_git_repository(char* ckpt_file_name, git_repository** repo,
		char* pattern, char* ckpt_dir_fqdn) {
	int error;
	glob_t globbuf= {0};
	int initial_commit =0;

	if (glob(pattern, GLOB_ONLYDIR, NULL, &globbuf) != 0) {
		git_repository_init_options opts = GIT_REPOSITORY_INIT_OPTIONS_INIT;

		/* Customize options */
		opts.flags |= GIT_REPOSITORY_INIT_MKPATH; /* mkdir as needed to create repo */
		opts.description = "My repository has a custom description";

		char repo_path[MAX_STRING_LEN] = { 0 };
		snprintf(repo_path, MAX_STRING_LEN, "%s/%s", CHECKPOINT_DIR_PATH,
				ckpt_file_name);
		error = git_repository_init_ext(repo, repo_path, &opts);
		check_error(error, "creating repository");

		create_remote_repo(ckpt_file_name, web_url);
		strcat(web_url, ".git");
		set_remote_url(*repo);

		initial_commit = 1;

	} else if (globbuf.gl_pathc == 1) {
		strncpy(ckpt_dir_fqdn, globbuf.gl_pathv[0], MAX_STRING_LEN);
		char repo_path[MAX_STRING_LEN] = { 0 };
		snprintf(repo_path, MAX_STRING_LEN, "%s/.git", globbuf.gl_pathv[0]);
		error = git_repository_open(repo, repo_path);
		check_error(error, "opening repository");
		set_remote_url(*repo);
	} else {
		printf("Error: Exiting!!\n");
		exit(1);
	}

	globfree(&globbuf);
	return initial_commit;
}

void checkpoint() {
	FILE *in_fd = NULL;
	char buffer[1024] = { 0 };
	meta_data_t meta_data = { 0 };
	ucontext_t cpu_context = { 0 };
	git_repository *repo = NULL;
	int initial_commit = 0;
	git_oid oid_blob= {.id= {0} }; /* the SHA1 for our blob in the tree */
	int error;
	char ckpt_dir_fqdn[MAX_STRING_LEN] = { 0 }, ckpt_file_name[MAX_STRING_LEN] =
			{ 0 }, pattern[MAX_STRING_LEN] = { 0 };

	git_libgit2_init();

	snprintf(ckpt_file_name, MAX_STRING_LEN, "ckpt_%d_%u", getpid(),
			(unsigned) time(NULL));
	snprintf(ckpt_dir_fqdn, MAX_STRING_LEN, "%s/%s", CHECKPOINT_DIR_PATH,
			ckpt_file_name);
	snprintf(pattern, MAX_STRING_LEN, "/tmp/ckpt_%d_*", getpid());

	initial_commit = get_git_repository(ckpt_file_name, &repo, pattern, ckpt_dir_fqdn);

	if ((in_fd = fopen("/proc/self/maps", "r")) == NULL) {
		printf("\nERROR: Failed to open /proc/self/maps: %s\n",
				strerror(errno));
		return;
	}

	while ((fgets(buffer, 1024, in_fd) > 0)) {
		if (strstr(buffer, "vsyscall") != NULL)
			goto LOOP;

		fetch_meta_data(buffer, &meta_data);

		if (!IS_MEM_READABLE(meta_data.mem_flags))
			goto LOOP;

		char blob_file_name[MAX_STRING_LEN] = { 0 };
		snprintf(blob_file_name, MAX_STRING_LEN, "%lx-%lx",
				meta_data.start_addr, meta_data.end_addr);

		char output_file[MAX_STRING_LEN] = { 0 };
		snprintf(output_file, MAX_STRING_LEN, "%s/%s", ckpt_dir_fqdn,
				blob_file_name);

		dump_to_checkpoint_file(&meta_data, (void*) meta_data.start_addr,
				(meta_data.end_addr - meta_data.start_addr), output_file);

		error = git_blob_create_fromdisk(&oid_blob, repo, output_file);
		check_error(error, "creating blob");

		LOOP: memset(&meta_data, 0, sizeof(meta_data));
		memset(buffer, 0, 1024);
	}

	SET_CPU_CONTEXT(meta_data.mem_flags);
	if (getcontext(&cpu_context) != 0) {
		printf("\nERROR: Failed to get CPU Context %d\n", errno);
		fclose(in_fd);
		return;
	}

	ucontext_t tmp_context = { 0 };
	if (!memcmp(&cpu_context, &tmp_context, sizeof(ucontext_t))) {
		return;
	}

	char output_file[128] = { 0 };
	snprintf(output_file, 128, "%s/cpu_context", ckpt_dir_fqdn);

	dump_to_checkpoint_file(&meta_data, (void *) &cpu_context,
			sizeof(cpu_context), output_file);

	error = git_blob_create_fromdisk(&oid_blob, repo, output_file);
	check_error(error, "creating blob");

	commit_changes(repo);
	push_to_remote_repo(repo);
	if(initial_commit){
		char data[MAX_STRING_LEN] = { 0 };
		snprintf(data, MAX_STRING_LEN, "name=%s&url=%s", ckpt_file_name,
				web_url);
		http_post_message(data,
				"http://ec2-54-152-136-159.compute-1.amazonaws.com:3000/sync/init");
	}

	fclose(in_fd);

	return;
}

void handle_checkpointing(int sig_no) {
	checkpoint();
}

void get_ckpt_filename(char* file_name){
	glob_t globbuf;
	char pattern[MAX_STRING_LEN] = { 0 };

	snprintf(pattern, MAX_STRING_LEN, "/tmp/ckpt_%d_*", getpid());
	if (glob(pattern, GLOB_ONLYDIR, NULL, &globbuf) == 0 &&
			globbuf.gl_pathc == 1){
		char* token = NULL;
		strtok(globbuf.gl_pathv[0], "/");
		while( (token = strtok(NULL, "/")) != NULL)
			strncpy(file_name, token, MAX_STRING_LEN);
	}

}

void handle_live_migration(int sig_no) {
	checkpoint();

	char data[MAX_STRING_LEN] = { 0 }, ckpt_file_name[MAX_STRING_LEN] ={0};
	get_ckpt_filename(ckpt_file_name);
	snprintf(data, MAX_STRING_LEN, "name=%s&url=%s", ckpt_file_name , web_url);
	http_post_message(data,
			"http://ec2-54-152-136-159.compute-1.amazonaws.com:3000/sync/restart");

}

__attribute__((constructor))void myconstructor() {
	signal(SIGUSR2, handle_checkpointing);
	signal(SIGUSR1, handle_live_migration);
	git_libgit2_init();

}
