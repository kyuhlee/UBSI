#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define UENTRY 0xffffff9c
#define UEXIT 0xffffff9b
#define MREAD 0xffffff38
#define MWRITE 0xfffffed4

using namespace std;

static inline void loadBar(long x, long n, int r, int w)
{
    // Only update r times.
//    if ( x % (n/r +1) != 0 ) return;
 
    // Calculuate the ratio of complete-to-incomplete.
    float ratio = x/(float)n;
    int   c     = ratio * w;
 
    // Show the percentage complete.
    printf("%3d%% [", (int)(ratio*100) );
 
    // Show the load bar.
    for (int x=0; x<c; x++)
       printf("=");
 
    for (int x=c; x<w; x++)
       printf(" ");
 
    // ANSI Control codes to go back to the
    // previous line and clear it.
    printf("]\n\033[F\033[J");
}

bool get_succ(char *buf)
{
		char *ptr;
		char succ[16];
		int i=0;

		ptr = strstr(buf, " success=");
		if(ptr == NULL) {
				//printf("PTR NULL: %s\n", buf);
				return false;
		}
		ptr+=9;

		for(i=0; ptr[i] != ' '; i++)
		{
				succ[i] = ptr[i];
		}
		succ[i] = '\0';
		//printf("success = %s: %s", succ, buf);
		if(strncmp(succ, "yes", 3) == 0) return true;
		else false;
}

#define MAX 20
int main(int argc, char** argv)
{
		long uread[MAX], uwrite[MAX], uentry, uexit, other, total;

		for(int i = 0; i < MAX; i++) {
				uread[i] = uwrite[i] = 0;
		}
		uentry = uexit = other = total = 0;

		if(argc < 2) {
				printf("usgae: %s audit.log\n", argv[0]);
				return 0;
		}

		FILE *log_fd = fopen(argv[1], "r");
		if(log_fd == NULL) {
				printf("file open error! %s\n", argv[1]);
				return 0;
		}

		int j, sysno;
		char *ptr, buf[60480];
		long fp, fend, fcur;
		long a0, a1;
		bool succ;

		fseek(log_fd, 0L, SEEK_END);
		fend = ftell(log_fd);
		fseek(log_fd, 0L, SEEK_SET);

	 printf("File Read...\n");
		while(!feof(log_fd)) {
				fp = ftell(log_fd);

				if(j++ > 10000) {
						loadBar(fp, fend, 10, 50);
						j = 0;
				}
				fgets(buf, 60480, log_fd);
				ptr = strstr(buf, "syscall=");
				if(ptr == NULL) {
						continue;
				}

				sscanf(ptr, "syscall=%d", &sysno);
				if(sysno == 62)
				{
						ptr = strstr(buf, " a0=");
						a0 = strtol(ptr+4, NULL, 16);
						if(a0 == UENTRY) {
								uentry++;
						} else if(a0 == UEXIT) {
								uexit++;
						} else if(a0 == MREAD || a0 == MWRITE) {
								ptr = strstr(ptr, " a1=");
								a1 = strtol(ptr+4, NULL, 16);
								if(a0 == MREAD) uread[a1]++;
								else uwrite[a1]++;
						} else {
								if(get_succ(buf)) other++;
						}
				} else {
						if(get_succ(buf)) other++;
				}
		}
		fclose(log_fd);

		for(int i = 0; i < MAX; i++)
		{
				total += uread[i];
				total += uwrite[i];
		}

		total += uentry;
		total += uexit;
		total += other;

		for(int i = 0; i < MAX; i++)
		{
				if(uread[i] > 0) printf("MREAD[%d] = %ld (%.2f\%)\n", i, uread[i], (float)(uread[i]*100) / (float) total);
		}

		for(int i = 0; i < MAX; i++)
		{
				if(uwrite[i] > 0) printf("MWRITE[%d] = %ld (%.2f\%)\n", i, uwrite[i], (float)(uwrite[i]*100) / (float)total);
		}

		printf("UENTRY = %ld (%.2f\%)\n", uentry, (float)(uentry*100) / (float)total);
		printf("UEXIT = %ld (%.2f\%)\n", uexit, (float)(uexit*100) / (float)total);
		printf("Other Syscall = %ld (%.2f\%)\n", other, (float)(other*100) / (float)total);
		printf("Total Syscall = %ld (%.2f\%)\n", total, (float)(total*100) / (float)total);
}
