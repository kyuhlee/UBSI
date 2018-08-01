#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "UBSI.h"
#include <stdint.h>

#define MAX 50

int main(int argc, char **argv) {
		int i, n, fd_in, fd_out;
		char init;
		char fname_in[128], fname_out[128], buffer[16];

		UBSI_MEM_WRITE(&init);
		init = 'c';
		for(i = 0; i < MAX; i++)
		{
				sleep(1);
				UBSI_LOOP_ENTRY(1);
				sprintf(fname_in, "input/data%02d.txt", i);
				sprintf(fname_out, "output/output%02d.txt", i);

				UBSI_MEM_READ(&init);
				if(init == 'a') ;
				fd_in = open(fname_in, O_RDONLY);
				if(fd_in < 0) {
						printf("file open fails: %s\n", fname_in);
						continue;
				}

				fd_out = open(fname_out, O_RDWR|O_CREAT, 0644);
				if(fd_out < 0) {
						printf("file open fails: %s\n", fname_out);
						continue;
				}

				n = read(fd_in, buffer, 16);
				n = write(fd_out, buffer, n);

				close(fd_in);
				close(fd_out);
		}
		UBSI_LOOP_EXIT(1);
}
