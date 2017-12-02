#include <stdio.h>
#include <stdlib.h>

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

int main(int argc, char **argv)
{
		FILE *fp, *out;
		char buf[4096], name[64];
		int i = 0;
		long fend, fcur;

		if(argc < 3)  {
				printf("usage: ./a.out max_auditlog_num, out_filename\n");
				return 0;
		}
		
		out = fopen(argv[2], "w");
		if(out == NULL) {
				printf("file open error: %s\n", argv[2]);
				return 0;
		}

		for(int i = 0; i <= atoi(argv[1]); i++)
		{
				if(i == 0) sprintf(name, "audit.log");
				else sprintf(name, "audit.log.%d", i);
				
				printf("file: %s\n", name);
				fp = fopen(name, "r");
				if(fp == NULL) {
						printf("file open error: %s\n", name);
						continue;
				}
				fseek(fp, 0L, SEEK_END);
				fend = ftell(fp);
				fseek(fp, 0L, SEEK_SET);

				fgets(buf, 4096, fp);
				int j = 0;
				while(!feof(fp)) 
				{
						if(j++ > 10000) {
								loadBar(ftell(fp), fend, 10, 50);
								j = 0;
						}
						fprintf(out, "%s", buf);
						fgets(buf, 4096, fp);
				}
				fclose(fp);
		}
		fclose(out);
}
