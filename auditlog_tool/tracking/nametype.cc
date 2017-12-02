#include <stdio.h>
#include <set>
#include <string>
#include <string.h>

using namespace std;

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
				
				if(ptr[i-1] == 29) ptr[i-1] = '\0';
				else ptr[i] = '\0';
				return string(ptr, i);
		}
		return string();
}

set<string> s;

int main(int argc, char **argv)
{
		FILE *fp;
		char buf[10240];

		if(argc < 2 || (fp = fopen(argv[1], "r")) == NULL) {
				printf("usage: ./a.out auditlog\n");
				return 0;
		}
		
		fgets(buf, 10240, fp);
		while(!feof(fp))
		{
				string str = extract_string(buf, " nametype=", 10);
				s.insert(str);
				fgets(buf, 10240, fp);
		}

		for(set<string>::iterator it = s.begin(); it != s.end(); it++)
		{
				printf("%s\n", it->c_str());
		}
}

