/*
 * myrestart.c
 *
 *  Created on: Jan 15, 2016
 *      Author: Praveen
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "ckpt.h"

char checkpoint_file[128];

void main(int argc, char** argv) {
	void* stack_ptr = (void*) 0x5300000;
	if (argc < 2) {
		printf(
				"ERROR: Insufficient Arguments\nUsage: myrestart <full-path-checkpoint-file>\n");
		exit(1);
	}

	int stack_size = 0x500000, mb = 1024 * 1024;
	strncpy(checkpoint_file, argv[1], 128);
	if ((stack_ptr = mmap((void*) stack_ptr, (size_t) stack_size,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0)) == MAP_FAILED) {
		printf("\nERROR: Failed to create new stack memory: %s\n",
				strerror(errno));
		exit(1);
	}

	stack_ptr += stack_size - mb;
	asm volatile ("mov %0,%%rsp;" : : "g" (stack_ptr) : "memory");
	restore_memory(checkpoint_file);
}
