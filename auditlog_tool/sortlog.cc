#include <stdio.h>
#include <string.h>
#include <map>
#include <set>

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

int main(int argc, char** argv)
{
		if(argc < 3) {
				printf("usgae: ./auditlog_sort audit.log, outfile\n");
				return 0;
		}
		FILE *log_fd = fopen(argv[1], "r");
		if(log_fd == NULL) {
				printf("file open error! %s\n", argv[1]);
				return 0;
		}

		FILE *out = fopen(argv[2], "w");

		map<long, set<long> > log_map;
		char *t, temp[60480];
		long fp, num, prev_num = 0;
		long fend, fcur;
	 int j = 0;

		fseek(log_fd, 0L, SEEK_END);
		fend = ftell(log_fd);
		fseek(log_fd, 0L, SEEK_SET);
	

	 printf("File Read and Sort!\n");
		while(!feof(log_fd)) {
				fp = ftell(log_fd);

				if(j++ > 10000) {
						loadBar(fp, fend, 10, 50);
						j = 0;
				}
				fgets(temp, 60480, log_fd);
				t = strstr(temp, (char*)":");
				if(t == NULL) {
						fprintf(stderr, "cannot find : %s\n\n", temp);
						return 0;
				}
				sscanf(t+1, "%ld", &num);
				if(num != prev_num) {
						map<long, set<long> >::iterator iter;
						iter = log_map.find(num);
						if(iter == log_map.end()) {
								set<long> t;
								t.insert(fp);
								log_map.insert(pair<long, set<long> >(num, t));
						} else {
								iter->second.insert(fp);
						}
				}
		}

	 printf("Write into %s file!\n", argv[2]);
		fseek(log_fd, 0, SEEK_SET);
		j = 0;
		for(map<long, set<long> >::iterator it = log_map.begin(); it != log_map.end(); it++)
		{
				fp = ftell(log_fd);

				if(j++ > 10000) {
						loadBar(fp, fend, 10, 50);
						j = 0;
				}

				for(set<long>::iterator it2 = it->second.begin(); it2 != it->second.end(); it2++)
				{
						fseek(log_fd, *it2, SEEK_SET);
						fgets(temp, 60480, log_fd);
						fprintf(out, "%s", temp);
				}
		}
		fclose(log_fd);
		fclose(out);
}
