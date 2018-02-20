#include <stdio.h>
#include <string.h>
#include <string>
#include <stdlib.h>

#define BUFFER_LENGTH   10000
#define FALSE 0
#define TRUE		1

using namespace std;

FILE *fout;
long long u0, u1;

void loadBar(long x, long n, int r, int w)
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

string extract_string(char *s, const char *needle, int size)
{
		char *ptr;

		ptr = strstr(s, needle);

		if(ptr)
		{
				ptr+=size;
				if(ptr[0] == '"') ptr++;
				int i=0;
				while(ptr[i] != ' ' && ptr[i] != '\n' && ptr[i] != '\0')
				{
						i++;
				}
				if(ptr[i-1] == '"') i--;

				return string(ptr, i);
		}
		return string();
}


int extract_int(char *s, const char *needle, int size, int *store)
{
		char *ptr;

		ptr = strstr(s, needle);

		//if(ptr && sscanf(ptr+size, "%ld", store) > 0) return 1;
		if(ptr)
		{
				*store = strtol(ptr+size, NULL, 10);
				return 1;
		}

		return 0;
}

int count = 0;
void process_buffer(char *buf)
{
		string comm;
		string exe;
		int unitid, sysno;

		comm = extract_string(buf, "comm=", 5);
		exe = extract_string(buf, "exe=", 4);
		extract_int(buf, "unitid=", 7, &unitid);
		extract_int(buf, "syscall=", 8, &sysno);
		
		if(unitid == 0) u0++;
		else u1++;
		//printf("%d, sysno %d, %s, %s\n", unitid, sysno, comm.c_str(), exe.c_str());
		if(count == 0) {
				fprintf(fout, "INSERT INTO e2_pandex_ripe (sysno, unitid, comm, exe) VALUES ");
		} else fprintf(fout, ",");
		
		fprintf(fout, "(%d, %d, \"%s\", \"%s\")", sysno, unitid, comm.c_str(), exe.c_str());
		if(++count >= 10000) {
				count = 0;
				fprintf(fout, ";\n");
		} 
}

int main(int argc, char** argv)
{
		char buffer[BUFFER_LENGTH];

		if(argc < 3) {
				printf("./XXX <log file name> <output file name>\n");
				return 0;
		}
		
		FILE *fp = fopen(argv[1], "r");
		fout = fopen(argv[2], "w");
		long fend, fcur, ftmp;

		if(fp == NULL || fout == NULL) {
				printf("Invalid log: ./XXX <log file name>\n");
				return 0;
		}
		//FILE *fp = stdin;

		fseek(fp, 0L, SEEK_END);
		fend = ftell(fp);
		fseek(fp, 0L, SEEK_SET);
		fcur = ftell(fp);
		int  i =0;

		do{
				while (TRUE) {
						memset(&buffer, 0, BUFFER_LENGTH);
						if(fgets(& buffer[0], BUFFER_LENGTH, fp) == NULL) {
								fprintf(stderr, "Reached the end of file (%s).\n", argv[1]);
								break;
						}
						process_buffer(buffer);
						fcur = ftell(fp);

						if(i++ > 10000) {
								loadBar(fcur, fend, 10, 50);
								i = 0;
						}
				}
		} while (FALSE);

		fprintf(fout, ";");

		printf("unitid==0: %lld, unitid>0: %lld\n", u0, u1);
}


