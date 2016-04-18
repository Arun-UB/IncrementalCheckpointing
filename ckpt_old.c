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
	char buffer[1024] = { 0 };
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

int Write(int fd, const void* buffer, int len)
{
	int ret = -1;
	while( (ret = write(fd, buffer, len)) != len)
	{
		if(ret < 0)
		{
			printf("\nERROR: Failed to write to checkpoint image: %s\n", strerror(errno));
			return ret;
		}
		len -= ret;
		buffer += ret;
	}
	return ret;
}

void checkpoint() {
	FILE *in_fd = NULL;
	int out_fd = -1;
	char buffer[1024] = { 0 };
	meta_data_t meta_data = { 0 };
	ucontext_t cpu_context = { 0 };

	if ((in_fd = fopen("/proc/self/maps", "r")) == NULL) {
		printf("\nERROR: Failed to open /proc/self/maps: %s\n",
				strerror(errno));
		return;
	}

	if ((out_fd = open("myckpt", O_WRONLY | O_CREAT | O_TRUNC,
	S_IRWXU | S_IRGRP | S_IROTH)) == -1) {
		printf("\nERROR: Failed to open myckpt: %s\n", strerror(errno));
		fclose(in_fd);
		return;
	}

	while ((fgets(buffer, 1024, in_fd) > 0)) {
		if (strstr(buffer, "vsyscall") != NULL)
			goto LOOP;

		fetch_meta_data(buffer, &meta_data);

		if (!IS_MEM_READABLE(meta_data.mem_flags))
			goto LOOP;

		if( Write(out_fd, (void *)&meta_data, sizeof(meta_data)) < 0)
			goto EXIT;

		if( Write(out_fd, (void *)meta_data.start_addr,
				(meta_data.end_addr - meta_data.start_addr)) < 0)
			goto EXIT;

		LOOP: memset(&meta_data, 0, sizeof(meta_data));
		memset(buffer, 0, 1024);
	}

	SET_CPU_CONTEXT(meta_data.mem_flags);
	if( Write(out_fd, (void *)&meta_data, sizeof(meta_data)) < 0)
		goto EXIT;;

	if (getcontext(&cpu_context) != 0)
		printf("\nERROR: Failed to get CPU Context %s\n", strerror(errno));
	else {
		write(out_fd, (void *)&cpu_context, sizeof(cpu_context));
	}

	EXIT:
	fclose(in_fd);
	close(out_fd);
}

void handle_checkpointing(int sig_no) {
	checkpoint();
}

__attribute__((constructor))void myconstructor() {
	signal(SIGUSR2, handle_checkpointing);
}
