/*
 * checkpoint.c
 *
 *  Created on: Jan 15, 2016
 *      Author: Praveen
 */
#include <stdio.h>
#include <unistd.h>

void main(int argc, char** argv) {
	while (1) {
		printf(".");
		fflush(stdout);
		sleep(1);
	}
}

