#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
		FILE *fp;
		char tmp[1048576];
		
		int begin, size;
		if(argc < 4 || (fp = fopen(argv[1], "r")) == NULL) {
				printf("usage: a.out logfile fp_start size\n");
				return 0;
		}
		
		begin = atoi(argv[2]);
		size = atoi(argv[3]);

		printf("FILE %s, fp %d, size %d\n",argv[1], begin, size);

		fseek(fp, begin, SEEK_SET);
		fread(tmp, size, 1, fp);

		printf("%s", tmp);
}

