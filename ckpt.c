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
	git_oid oid_tree; /* the SHA1 for our tree in the commit */
	git_tree * tree_cmt; /* our tree in the commit */
	git_signature *author;
	git_oid oid_commit; /* the SHA1 for our initial commit */
	git_index *index;
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
		git_oid oid_parent_commit; /* the SHA1 for last commit */

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
	FILE* in_fd;
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

			git_oid oid_blob;
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

void get_git_repository(char* ckpt_dir_fqdn, git_repository** repo) {
	struct stat st = { 0 };
	int error;

	if (stat(ckpt_dir_fqdn, &st) == -1) {
		git_repository_init_options opts = GIT_REPOSITORY_INIT_OPTIONS_INIT;

		/* Customize options */
		opts.flags |= GIT_REPOSITORY_INIT_MKPATH; /* mkdir as needed to create repo */
		opts.description = "My repository has a custom description";

		error = git_repository_init_ext(repo, ckpt_dir_fqdn, &opts);
		check_error(error, "creating repository");

	} else {
		char repo_path[MAX_STRING_LEN] = { 0 };
		snprintf(repo_path, MAX_STRING_LEN, "%s/.git", ckpt_dir_fqdn);
		error = git_repository_open(repo, repo_path);
		check_error(error, "opening repository");
	}
}

void checkpoint() {
	FILE *in_fd = NULL;
	char buffer[1024] = { 0 };
	meta_data_t meta_data = { 0 };
	ucontext_t cpu_context = { 0 };
	git_repository *repo = NULL;
	git_oid oid_blob; /* the SHA1 for our blob in the tree */

	int error;

	char ckpt_dir_fqdn[MAX_STRING_LEN] = { 0 };
	snprintf(ckpt_dir_fqdn, MAX_STRING_LEN, "/tmp/ckpt_%d", getpid());

	git_libgit2_init();
	get_git_repository(ckpt_dir_fqdn, &repo);

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

	ucontext_t tmp_context = {0};
	if( !memcmp(&cpu_context, &tmp_context, sizeof(ucontext_t) ) ){
		return;
	}

	char output_file[128] = { 0 };
	snprintf(output_file, 128, "%s/cpu_context", ckpt_dir_fqdn);

	dump_to_checkpoint_file(&meta_data, (void *) &cpu_context,
			sizeof(cpu_context), output_file);

	error = git_blob_create_fromdisk(&oid_blob, repo, output_file);
	check_error(error, "creating blob");

	commit_changes(repo);
	fclose(in_fd);
	return;
}

void handle_checkpointing(int sig_no) {
	git_libgit2_init();
	checkpoint();
	git_libgit2_shutdown();
}

__attribute__((constructor))void myconstructor() {
	signal(SIGUSR2, handle_checkpointing);

}
