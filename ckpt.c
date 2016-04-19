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
	char *tmp_buffer = strdup(buffer), *addr_range = NULL, *flags = NULL;
	int index = 0;

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

	free(tmp_buffer);
}

void unmap_old_stack() {
	FILE *in_fd = NULL;
	char buffer[1024] = { 0 };
	meta_data_t meta_data = { 0 };

	if ((in_fd = fopen("/proc/self/maps", "r")) == NULL) {
		printf("ERROR:Failed to open /proc/self/maps: %s\n", strerror(errno));
		exit(1);
	}

	while ((fgets(buffer, 1024, in_fd) > 0)) {
		fetch_meta_data(buffer, &meta_data);

		if (!IS_STACK_MEMORY(meta_data.mem_flags))
			goto LOOP;

		if (munmap((void*) meta_data.start_addr,
				(meta_data.end_addr - meta_data.start_addr)) != 0) {
			printf("ERROR: Failed to unmap original Stack Memory : %s\n",
					strerror(errno));
			exit(1);
		}

		break;

		LOOP: memset(&meta_data, 0, sizeof(meta_data));
		memset(buffer, 0, 1024);
	}
}

int get_protection_flags(uint8_t flags) {
	int flag = PROT_EXEC;

	if (IS_MEM_READABLE(flags))
		flag |= PROT_READ;

	if (IS_MEM_WRITABLE(flags))
		flag |= PROT_WRITE;

	if (IS_MEM_EXECUTABLE(flags))
		flag |= PROT_EXEC;

	return flag;
}

int get_map_flags(uint8_t flags) {
	int flag = MAP_ANONYMOUS | MAP_FIXED;

	if (IS_MEM_PRIVATE(flags))
		flag |= MAP_PRIVATE;
	else
		flag |= MAP_SHARED;

	return flag;
}

void restore_checkpoint_app_context(char* checkpoint_file) {
	int fd = -1;
	void* mem_ptr = NULL;
	meta_data_t meta_data = { 0 };
	ucontext_t *cpu_context = NULL;

	if ((fd = open(checkpoint_file, O_RDONLY)) == -1) {
		printf("ERROR: Failed to open %s: %s\n", checkpoint_file,
				strerror(errno));
		close(fd);
		exit(1);
	}

	while (read(fd, &meta_data, sizeof(meta_data)) > 0) {
		if ( IS_CPU_CONTEXT(meta_data.mem_flags))
			break;

		if ((mem_ptr = mmap((void*) meta_data.start_addr,
				(meta_data.end_addr - meta_data.start_addr),
				PROT_WRITE, get_map_flags(meta_data.mem_flags), -1, 0))
				== MAP_FAILED) {
			printf("ERROR: Failed to create new stack memory\n");
			exit(1);
		}

		read(fd, mem_ptr, (meta_data.end_addr - meta_data.start_addr));

		if (mprotect(mem_ptr, (meta_data.end_addr - meta_data.start_addr),
				get_protection_flags(meta_data.mem_flags)) != 0) {
			printf("ERROR: Failed to set the memory protection flags\n");
			exit(1);
		}

		memset(&meta_data, 0, sizeof(meta_data));
		mem_ptr = NULL;

	}

	if ((cpu_context = mmap(NULL, sizeof(ucontext_t),
	PROT_WRITE | PROT_READ | PROT_EXEC,
	MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
		printf("\nERROR: Failed to create new stack memory: %s\n",
				strerror(errno));
		exit(1);
	}

	read(fd, cpu_context, sizeof(ucontext_t));
	setcontext(cpu_context);

	printf("\nERROR: Failed to restore checkpointed image :%s\n",
			strerror(errno));
	exit(1);
}

void restore_memory(char* checkpoint_file) {
	unmap_old_stack();
	restore_checkpoint_app_context(checkpoint_file);
}

int Write(int fd, const void* buffer, int len) {
	int ret = -1;
	while ((ret = write(fd, buffer, len)) != len) {
		if (ret < 0) {
			printf("\nERROR: Failed to write to checkpoint image: %s\n",
					strerror(errno));
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

	exit(1);
}

static void dump_to_checkpoint_file(meta_data_t* meta_data, void* data, int len,
		char* output_file) {
	int out_fd;

	if ((out_fd = open(output_file,
	O_WRONLY | O_CREAT | O_TRUNC,
	S_IRWXU | S_IRGRP | S_IROTH)) == -1) {
		printf("\nERROR: Failed to open ckpt file: %s\n", strerror(errno));
		exit(1);
	}

	if (Write(out_fd, (void *) meta_data, sizeof(meta_data)) < 0) {
		printf("\nERROR: Failed to write to ckpt file: %s\n", strerror(errno));
		exit(1);
	}

	if (Write(out_fd, (void *) data, len) < 0) {
		printf("\nERROR: Failed to open ckpt file: %s\n", strerror(errno));
		exit(1);
	}

	close(out_fd);

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

void checkpoint() {
	FILE *in_fd = NULL;
	char buffer[1024] = { 0 };
	meta_data_t meta_data = { 0 };
	ucontext_t cpu_context = { 0 };
	git_repository *repo = NULL;
	git_oid oid_blob; /* the SHA1 for our blob in the tree */

	struct stat st = { 0 };
	int error;

	char ckpt_dir_fqdn[MAX_STRING_LEN] = { 0 };
	snprintf(ckpt_dir_fqdn, MAX_STRING_LEN, "/tmp/ckpt_%d", getpid());

	if ((in_fd = fopen("/proc/self/maps", "r")) == NULL) {
		printf("\nERROR: Failed to open /proc/self/maps: %s\n",
				strerror(errno));
		return;
	}

	if (stat(ckpt_dir_fqdn, &st) == -1) {
		git_repository_init_options opts = GIT_REPOSITORY_INIT_OPTIONS_INIT;

		/* Customize options */
		opts.flags |= GIT_REPOSITORY_INIT_MKPATH; /* mkdir as needed to create repo */
		opts.description = "My repository has a custom description";

		error = git_repository_init_ext(&repo, ckpt_dir_fqdn, &opts);
		check_error(error, "creating repository");

	} else {
		char repo_path[MAX_STRING_LEN] = { 0 };
		snprintf(repo_path, MAX_STRING_LEN, "%s/.git", ckpt_dir_fqdn);
		error = git_repository_open(&repo, repo_path);
		check_error(error, "opening repository");
	}

	while ((fgets(buffer, 1024, in_fd) > 0)) {
		if (strstr(buffer, "vsyscall") != NULL)
			goto LOOP;

		fetch_meta_data(buffer, &meta_data);

		if (!IS_MEM_READABLE(meta_data.mem_flags))
			goto LOOP;

		char blob_file_name[MAX_STRING_LEN] = { 0 };
		snprintf(blob_file_name, MAX_STRING_LEN, "%ld", meta_data.start_addr);

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

	char output_file[MAX_STRING_LEN] = { 0 };
	snprintf(output_file, MAX_STRING_LEN, "%s/cpu_context", ckpt_dir_fqdn);

	SET_CPU_CONTEXT(meta_data.mem_flags);
	if (getcontext(&cpu_context) != 0) {
		printf("\nERROR: Failed to get CPU Context %s\n", strerror(errno));
		goto EXIT;
	} else {
		dump_to_checkpoint_file(&meta_data, (void *) &cpu_context,
				sizeof(cpu_context), output_file);
	}

	error = git_blob_create_fromdisk(&oid_blob, repo, output_file);
	check_error(error, "creating blob");

	commit_changes(repo);
	EXIT: fclose(in_fd);
}

void handle_checkpointing(int sig_no) {
	checkpoint();
}

__attribute__((constructor))void myconstructor() {
	git_libgit2_init();
	signal(SIGUSR2, handle_checkpointing);

}
