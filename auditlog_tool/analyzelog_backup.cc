#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <map>

#define UENTRY 0xffffff9c
#define UEXIT 0xffffff9b
#define MREAD1 0xffffff38
#define MREAD2 0xffffff37
#define MWRITE1 0xfffffed4
#define MWRITE2 0xfffffed3

//thread status
#define ENTRY 0x1
#define EXITED 0x10
#define MEMWRITE 0x100
#define MEMREAD 0x1000
#define SYSCALL 0x10000

std::map<long,int> mymap; // pid (threadid), status

typedef struct {
		int uEntry;
		int uExit;
		int mRead;
		int mWrite;
		int syscall;

		int unusedEntry;
		int unusedExit;
		int unusedRead;
		int unusedWrite;
} STAT;

STAT stat;
char comm[64];

bool is_selected_syscall(int S, bool succ)
{
		return true;
		//return false;
		if(!succ) return false;
		if(S == 1 || S == 2 || S == 3 || S == 18 || S == 20 || S == 296 || S == 41 || S == 42 ||
				 S == 43|| S == 44|| S == 45|| S == 46 || S == 47 || S == 56  || S == 57 || S == 58 ||
					S == 59|| S == 2 || S ==293|| S == 22 || S ==288 || S == 0 || S == 17 || S == 19 || 
					S ==295|| S == 82|| S ==264|| S == 87 || S == 86 || S == 62|| S == 9  || S == 10 ||
					S == 32|| S == 33|| S ==292)
				return true;

		return false;
}

void UBSI_event(long pid, long a0, long a1)
{
		std::map<long, int>::iterator it;
		it = mymap.find(pid);
		if(it == mymap.end()) {
				mymap[pid] = 0;
				it = mymap.find(pid);
		}

		switch(a0) {
				case UENTRY: 
						stat.uEntry++;
						if((it->second & ENTRY) && it->second < MEMWRITE) stat.unusedEntry++;
						it->second = ENTRY;
						break;
				case UEXIT: 
						if(it->second == 0) stat.unusedExit++;
						else if((it->second & ENTRY) && it->second < MEMWRITE) {
								stat.unusedEntry++;
								stat.unusedExit++;
						}
						stat.uExit++;
						it->second = EXITED;
						break;
				case MREAD1:
				case MREAD2:
						stat.mRead++;
						if((it->second & ENTRY) == false) stat.unusedRead++;
						it->second = it->second | MEMREAD;
						break;
				case MWRITE1:
				case MWRITE2:
						stat.mWrite++;
						if((it->second & ENTRY) == false) stat.unusedWrite++;
						it->second = it->second | MEMWRITE;
						break;
		}
}

void non_UBSI_event(long pid, int sysno, bool succ)
{
		if(!is_selected_syscall(sysno, succ))  return;

		std::map<long, int>::iterator it;
		it = mymap.find(pid);
		if(it == mymap.end()) {
				mymap[pid] = 0;
				it = mymap.find(pid);
		}
		
		it->second = it->second | SYSCALL;
		stat.syscall++;
}

void get_comm(char *buf)
{
		char *ptr;
		int i=0;

		ptr = strstr(buf, " comm=");
		ptr+=6;

		for(i=0; ptr[i] != ' '; i++)
		{
				comm[i] = ptr[i];
		}
		comm[i] = '\0';
		printf("comm = %s: %s", comm, buf);
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

void line(char *buf)
{
		char *ptr;
		int sysno;
		long a0, a1, pid;
		char comm[64];
		bool succ;

		if(strncmp(buf, "type=SYSCALL",12) != 0) return;  
		//printf("buf = %s\n", buf);
		ptr = strstr(buf, " syscall=");
		if(ptr == NULL) {
				printf("ptr = NULL\n");
				return;
		}
		//sysno = atoi(ptr);
		sysno = strtol(ptr+9, NULL, 10);
		//printf("SYSNO %d: %s\n", sysno, ptr);
		
		ptr = strstr(ptr, " pid=");
		pid = strtol(ptr+5, NULL, 10);

		succ = get_succ(buf);
		//if(!succ) printf("succ=NO!, %s\n", buf);
		//get_comm(buf);

		if(sysno == 62)
		{
				ptr = strstr(buf, " a0=");
				a0 = strtol(ptr+4, NULL, 16);
				if(a0 == UENTRY || a0 == UEXIT || a0 == MREAD1 || a0 == MREAD2 || a0 == MWRITE1 || a0 ==MWRITE2)
				{
						ptr = strstr(ptr, " a1=");
						a1 = strtol(ptr+4, NULL, 16);
						UBSI_event(pid, a0, a1);
						//printf("pid %d, a0 %x, a1 %x: %s\n", pid, a0, a1, buf);
				} else {
						non_UBSI_event(pid, sysno, succ);
				}
		} else {
				non_UBSI_event(pid, sysno, succ);
		}
}


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
		FILE *fp;
		char buf[1024];
		int i = 0;
		long fend, fcur;

		if(argc < 2 || (fp=fopen(argv[1], "r")) ==NULL) {
				printf("usage: ./a.out filename\n");
				return 0;
		}
		
		fseek(fp, 0L, SEEK_END);
		fend = ftell(fp);
		fseek(fp, 0L, SEEK_SET);

		fgets(buf, 1024, fp);
		while(!feof(fp)) 
		{
				if(i++ > 10000) {
						loadBar(ftell(fp), fend, 10, 50);
						i = 0;
			 }
				//if(i++ > 20); return 0;
				line(buf);
				fgets(buf, 1024, fp);
		}
		int total_event = stat.uEntry+stat.uExit+stat.mRead+stat.mWrite+stat.syscall;
		printf("UENTRY %d\nUEXIT %d\nMREAD %d\nMWRITE %d\nSYSCALL %d\nTOTAL %d\n", stat.uEntry, stat.uExit, stat.mRead, stat.mWrite, stat.syscall, total_event);
		printf("Unused_Entry %d\nUnused_Exit %d\nUnused_Read %d\nUnused_Write %d\n", stat.unusedEntry, stat.unusedExit, stat.unusedRead, stat.unusedWrite);
}
