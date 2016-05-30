#include <stdio.h>
#include <string.h>
#include <map>
#include <set>

using namespace std;

int main(int argc, char** argv)
{
		if(argc < 2) {
				printf("usgae: ./auditlog_sort audit.log\n");
				return 0;
		}
		FILE *log_fd = fopen(argv[1], "r");
		if(log_fd == NULL) {
				printf("file open error! %s\n", argv[1]);
				return 0;
		}

		map<long, set<long> > log_map;
		char *t, temp[60480];
		long fp, num, prev_num = 0;
		while(!feof(log_fd)) {
				fp = ftell(log_fd);
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

		fseek(log_fd, 0, SEEK_SET);
		for(map<long, set<long> >::iterator it = log_map.begin(); it != log_map.end(); it++)
		{
				long map_num = it->first;
				for(set<long>::iterator it2 = it->second.begin(); it2 != it->second.end(); it2++)
				{
						fseek(log_fd, *it2, SEEK_SET);
						while(!feof(log_fd)) {
								fgets(temp, 60480, log_fd);
								t = strstr(temp, (char*)":");
								if(t == NULL) {
										fprintf(stderr, "cannot find : %s\n\n\n", temp);
										return 0;
								}
								sscanf(t+1, "%ld", &num);
								if(num == map_num) printf("%s", temp);
								else break;
						}
				}
		}
		fclose(log_fd);
}

