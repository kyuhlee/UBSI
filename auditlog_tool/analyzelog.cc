#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <map>
#include <set>
#include <assert.h>

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


typedef struct{
		int spid;
		int hasEntry;
		int syscall;
		int read;
		int write;
		std::map<long int, long> addr_all; // written addr for process (not thread), <addr, last_write_id>
		std::set<long int> addr; // written addr for unit
		std::map<long int, long> raddr; // read addr for unit // to check duplicated read <addr, last_written_id>
		long int r_addr;
		long int w_addr;
		long int bytes;
		long int cached_bytes;
} UnitDetail;

std::map<long, UnitDetail> unit; // pid (threadid), status

typedef struct {
		int uEntry;
		int uExit;
		int mRead;
		int mWrite;
		int syscall;						// selected syscalls
		int allSyscall;   // all syscalls
		int outSyscall;			// selected syscalls that invoked out of any units.
		
		long long syscallBytes;
		long long allSyscallBytes;
		long long outSyscallBytes;

		int unusedRead;			// mem_read that does not introduce any causality. 1. mem_read happened out of the unit, 2. target mem addr never being written.
		int unusedWrite;		// mem_write that does not introduce any causality: mem_write happened out of the unit.
		int unusedSyscall; // syscall that called out of any unit.
		int dupRead;						// mem_read that is duplicated, and does not make an effect. there was a previous mem_read to the same memory in the same unit and there is no new mem_write between the last mem_read and the current one.
		int dupWrite;			// duplicated mem_write. There was a previous mem_write to the same memaddr in the same unit.

		long long unusedReadBytes;
		long long unusedWriteBytes;
		long long unusedSyscallBytes;
		long long dupReadBytes;
		long long dupWriteBytes;

		int ignoredUnit; // Unit that does not have any syscalls.
		int ignoredUnitRead;
		int ignoredUnitWrite;
		int ignoredUnitEntry;
		int ignoredUnitExit;

		long long ignoredUnitBytes;

		int notIgnoredUnit;
		int notIgnoredUnitRead;
		int notIgnoredUnitUnusedRead;
		int notIgnoredUnitWrite;
		int notIgnoredUnitSyscall;
		int notIgnoredUnitEntry;
		int notIgnoredUnitExit;
		long long notIgnoredUnitBytes;

} STAT;

STAT stat;
char comm[64];

void cal_buf( long *tmp_size, long *tmp_thread)
{
		std::map<long, UnitDetail>::iterator it;

		(*tmp_size) = (*tmp_thread) = 0;
		for(it = unit.begin(); it != unit.end(); it++)
		{
				if(it->second.hasEntry && it->second.cached_bytes > 0) {
						(*tmp_size) += it->second.cached_bytes;
						(*tmp_thread)++;
				}
		}
}

bool is_selected_syscall(int S, bool succ, int bytes)
{
//		return true;
		//return false;
		stat.allSyscall++;
		stat.allSyscallBytes += bytes;
		if(!succ) 
				return false;
		
		switch(S) {
				case 0: case 19: case 1: case 20: case 44: case 45: case 46: case 47: case 86: case 88: case 56: case 57: case 58:
				case 59: case 2: case 85: case 257: case 259: case 133: case 32: case 33: case 292: case 49: case 43: case 288:
				case 42: case 82: case 105: case 113: case 90: case 22: case 293: case 76: case 77: case 40: case 87: case 263:
				stat.syscall++;
				stat.syscallBytes += bytes;
				return true;
		}
	//-S read -S readv -S write -S writev -S sendto -S recvfrom -S sendmsg -S recvmsg -S link -S symlink -S clone -S fork -S vfork 
	//-S execve -S open -S creat -S openat -S mknodat -S mknod -S dup -S dup2 -S dup3 -S bind -S accept -S accept4 
	//-S connect -S rename -S setuid -S setreuid -S setresuid -S chmod -S fchmod -S pipe -S pipe2 -S truncate -S ftruncate -S sendfile -S unlink -S unlinkat

/*		if(S == 1 || S == 2 || S == 3 || S == 18 || S == 20 || S == 296 || S == 41 || S == 42 ||
				 S == 43|| S == 44|| S == 45|| S == 46 || S == 47 || S == 56  || S == 57 || S == 58 ||
					S == 59|| S == 2 || S ==293|| S == 22 || S ==288 || S == 0 || S == 17 || S == 19 || 
					S ==295|| S == 82|| S ==264|| S == 87 || S == 86 || S == 62|| S == 9  || S == 10 ||
					S == 32|| S == 33|| S ==292)
		{
				stat.syscall++;
				return true;
		}
*/
		return false;
}

void UBSI_event(long pid, long a0, long a1, char *buf, int bytes)
{
		std::map<long, UnitDetail>::iterator it, sit;
		std::map<long int, long>::iterator tit, tit2;
		it = unit.find(pid);
		if(it == unit.end()) {
				UnitDetail ud;
				ud.syscall = ud.read = ud.write = ud.hasEntry = 0;
				ud.spid = pid;
				unit[pid] = ud;
				it = unit.find(pid);
				sit = it;
		} else {
				sit = unit.find(it->second.spid);
				if(sit == unit.end()) {
						assert(0);
				}
		}

		switch(a0) {
				case UENTRY: 
				case UEXIT: 
						if(a0 == UENTRY) stat.uEntry++;
						if(a0 == UEXIT) stat.uExit++;
						if(it->second.hasEntry) {
								if(it->second.syscall == 0 && (it->second.write == 0 || it->second.read == 0)) { // unit that can be ignored.
										stat.ignoredUnit++;
										stat.ignoredUnitEntry++;
										if(a0 == UEXIT) {
												stat.ignoredUnitExit++;
												stat.ignoredUnitBytes += bytes;
										}
										stat.ignoredUnitRead += it->second.read;
										stat.ignoredUnitWrite += it->second.write;
										stat.ignoredUnitBytes += it->second.bytes;

										std::set<long int>::iterator wit;
										for(wit = it->second.addr.begin(); wit != it->second.addr.end(); wit++)
										{
												sit->second.addr_all.erase(*wit);
										}
								} else { // unit that cannot be ignored.
										stat.notIgnoredUnit++;
										stat.notIgnoredUnitEntry++;
										if(a0 == UEXIT) stat.notIgnoredUnitExit++;
										stat.notIgnoredUnitRead += it->second.read;
										stat.notIgnoredUnitWrite += it->second.write;
										stat.notIgnoredUnitSyscall += it->second.syscall;
										stat.notIgnoredUnitBytes += it->second.bytes;
										/*std::set<long int>::iterator it2;
										for(it2 = it->second.addr.begin(); it2 != it->second.addr.end(); it2++)
										{
												sit->second.addr_all.insert(*it2);
										}*/
								}
						}
						if(a0 == UENTRY) it->second.hasEntry = 1;
						else it->second.hasEntry = 0;
						it->second.syscall = it->second.read = it->second.write = it->second.bytes = 0;
						it->second.cached_bytes = 0;
						it->second.addr.clear();
						it->second.raddr.clear();
						it->second.r_addr = it->second.w_addr = 0;
						if(a0 == UENTRY) {
								it->second.bytes = bytes;
								it->second.cached_bytes = bytes;
						}
						break;

				case MREAD1:
				case MREAD2:
						stat.mRead++;
						if(!it->second.hasEntry) 
						{
								stat.unusedRead++;
								stat.unusedReadBytes += bytes;
						} else {
								if(a0 == MREAD1) {
										it->second.r_addr = a1;
										it->second.r_addr = it->second.r_addr << 32;
								} else {
										it->second.r_addr += a1;

										tit = sit->second.addr_all.find(it->second.r_addr);
										if(tit == sit->second.addr_all.end()) {
												stat.unusedRead+=2;
												stat.unusedReadBytes += (2*bytes);
										} else {
												tit2 = it->second.raddr.find(it->second.r_addr);
												if(tit2 == it->second.raddr.end()) {
														it->second.raddr[it->second.r_addr] = tit->second;
														it->second.read+=2;
														it->second.bytes+= (2*bytes);
												} else {
														if(tit2->second == tit->second) {
																stat.dupRead+=2;
																stat.dupReadBytes += (2*bytes);
														} else {
																it->second.read+=2;
																it->second.bytes += (2*bytes);
																it->second.cached_bytes += (2*bytes);
														}
														tit2->second = tit->second;
												}
										}
								}
						}
						break;
				case MWRITE1:
				case MWRITE2:
						stat.mWrite++;
						if(!it->second.hasEntry) {
								stat.unusedWrite++;
								stat.unusedWriteBytes += bytes;
						} else {
								if(a0 == MWRITE1) {
										it->second.w_addr = a1;
										it->second.w_addr = it->second.w_addr << 32;
								} else {
										it->second.w_addr += a1;
										if(it->second.addr.find(it->second.w_addr) == it->second.addr.end()) {
												char *ptr;
												long event_id;

												it->second.write+=2;
												it->second.bytes+= (2*bytes);
												it->second.cached_bytes += (2*bytes);

												ptr = strstr(buf, ":");
												event_id = strtol(ptr+1, NULL, 10);

												std::map<long int, long>::iterator tit;

												it->second.addr.insert(it->second.w_addr);
												
												tit = sit->second.addr_all.find(it->second.w_addr);
												if(tit == sit->second.addr_all.end())
												{
														sit->second.addr_all[it->second.w_addr] = event_id;
												} else {
														tit->second = event_id;
												}
										} else {
												stat.dupWrite+=2;
												stat.dupWriteBytes += (2*bytes);
										}
								}
						}
						break;
		}
		if(it->second.syscall > 0 || (it->second.write > 0 && it->second.read > 0)) {
				it->second.cached_bytes = 0; // need to flush to disk
		}
}

void non_UBSI_event(long pid, int sysno, bool succ, char *buf, int bytes)
{
		char *ptr;
		long a2;
		long ret;
		int spid;

		std::map<long, UnitDetail>::iterator it, it2;

		if(!is_selected_syscall(sysno, succ, bytes))  return;
		
		if(succ == true && (sysno == 56 || sysno == 57 || sysno == 58)) // clone or fork
		{
				ptr = strstr(buf, " a2=");
				a2 = strtol(ptr+4, NULL, 16);

				ptr = strstr(buf, " exit=");
				ret = strtol(ptr+6, NULL, 10);
				
				if(a2 > 0) { // thread_creat event
						it2 = unit.find(pid);
						if(it2 == unit.end())
						{
								UnitDetail ud;
								ud.syscall = ud.read = ud.write = ud.hasEntry = ud.bytes = 0;
								ud.spid = pid;
								unit[pid] = ud;
								spid = pid;
						} else {
								spid = it2->second.spid;

						}
						it2 = unit.find(ret);
						if(it2 == unit.end()) {
								UnitDetail ud;
								ud.syscall = ud.read = ud.write = ud.hasEntry = ud.bytes = 0;
								ud.cached_bytes = 0;
								ud.spid = spid;
								unit[ret] = ud;
								//it2 = unit.find(ret);
						} else {
								it2->second.syscall = it2->second.read = it2->second.write = it2->second.hasEntry = it2->second.bytes = 0;
								it2->second.cached_bytes = 0;
								it2->second.r_addr = it2->second.w_addr = 0;
								it2->second.spid = spid;
								it2->second.addr_all.clear();
								it2->second.addr.clear();
						}
						printf("fork: child tid %d, pid %d, spid %d\n", ret, pid, spid);
				}
		} else if(succ == true && ( sysno == 59 || sysno == 322)) { // execve
						it2 = unit.find(pid);
						if(it2 == unit.end()) {
								UnitDetail ud;
								ud.syscall = ud.read = ud.write = ud.hasEntry = ud.bytes = 0;
								ud.cached_bytes = 0;
								ud.spid = pid;
								unit[pid] = ud;
						} else {
								it2->second.syscall = it2->second.read = it2->second.write = it2->second.hasEntry = it2->second.bytes = 0;
								it2->second.cached_bytes = 0;
								it2->second.r_addr = it2->second.w_addr = 0;
								it2->second.spid = pid;
								it2->second.addr_all.clear();
								it2->second.addr.clear();
						}
		}

		it = unit.find(pid);
		if(it == unit.end()) {
				stat.unusedSyscall++;
				stat.unusedSyscallBytes += bytes;
				stat.outSyscall++;
				stat.outSyscallBytes += bytes;
				return;
		}
		if(it->second.hasEntry) {
				it->second.syscall++;
				it->second.bytes += bytes;
				it->second.cached_bytes=0;
		} else {
				stat.outSyscall++;
				stat.outSyscallBytes += bytes;
		}
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

void syscall_handler(char *buf, int bytes)
{
		char *ptr;
		int sysno;
		long a0, a1, pid;
		char comm[64];
		bool succ;

		ptr = strstr(buf, " syscall=");
		if(ptr == NULL) {
				printf("ptr = NULL: %s\n", buf);
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
						UBSI_event(pid, a0, a1, buf, bytes);
						//printf("pid %d, a0 %x, a1 %x: %s\n", pid, a0, a1, buf);
				} else {
						non_UBSI_event(pid, sysno, succ, buf, bytes);
				}
		} else {
				non_UBSI_event(pid, sysno, succ, buf, bytes);
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
		char buf[1048576], buf2[1048576];
		int i = 0;
		long fend, fcur, ftmp;
		char *ptr;
		long eid, teid;
		long max_buf_size, max_thread;
		long tmp_size, tmp_thread;
		
		max_buf_size = max_thread =tmp_size = tmp_thread = 0;
		if(argc < 2 || (fp=fopen(argv[1], "r")) ==NULL) {
				printf("usage: ./a.out filename\n");
				return 0;
		}
		
		fseek(fp, 0L, SEEK_END);
		fend = ftell(fp);
		fseek(fp, 0L, SEEK_SET);
		
		fcur = ftell(fp);
		fgets(buf, 1048576, fp);
		while(!feof(fp)) 
		{

				if(strncmp(buf, "type=SYSCALL",12) != 0) {
						fcur = ftell(fp);
						fgets(buf, 1048576, fp);
						continue;
				}
					
				ptr = strstr(buf, ":");
				eid = strtol(ptr+1, NULL, 10);
				teid = eid;

				if(i++ > 1000) {
						cal_buf(&tmp_size, & tmp_thread);
						if(tmp_size > max_buf_size) {
								max_buf_size = tmp_size;
								max_thread = tmp_thread;
						}

						loadBar(fcur, fend, 10, 50);
						i = 0;
			 }

				while(!feof(fp) && eid == teid)
				{
						ftmp = ftell(fp);
						fgets(buf2, 1048576, fp);
						ptr = strstr(buf2, ":");
						if(ptr == NULL) {
								printf("buf: %s\n\nbuf2: %s\n", buf, buf2);
						} else {
								teid = strtol(ptr+1, NULL, 10);
						}
				}
						
				syscall_handler(buf, ftmp - fcur);
				fseek(fp, ftmp, SEEK_SET);
				fcur = ftmp;
				fgets(buf, 1048576, fp);
		}
		int total_event = stat.uEntry+stat.uExit+stat.mRead+stat.mWrite+stat.allSyscall;
		printf("UENTRY %d\nUEXIT %d\nMREAD %d\nMWRITE %d\nSYSCALL %d\nTOTAL %d\n", stat.uEntry, stat.uExit, stat.mRead, stat.mWrite, stat.allSyscall, total_event);
		printf("Not_important_syscall %d\n", stat.allSyscall - stat.syscall);
		printf("OutSyscall %d\n", stat.outSyscall);
		printf("Unused_Read %d\nUnused_Write %d\nUnused_syscall %d\n", stat.unusedRead, stat.unusedWrite, stat.unusedSyscall);
		printf("Dup_read %d\nDup_write %d\n", stat.dupRead, stat.dupWrite);
		printf("Ignored_Unit %d\nIgnored_entry %d\nIgnored_exit %d\nIgnored_read %d\nIgnored_write %d\n", stat.ignoredUnit, stat.ignoredUnitEntry, stat.ignoredUnitExit, stat.ignoredUnitRead, stat.ignoredUnitWrite);
		printf("Not_ignored_Unit %d\nNot_ignored_entry %d\nNot_ignored_exit %d\nNot_ignored_read %d\nNon_ignored_unused_read %d\nNot_ignored_write %d\nNot_ignored_syscall %d\n", stat.notIgnoredUnit, stat.notIgnoredUnitEntry, stat.notIgnoredUnitExit, stat.notIgnoredUnitRead,stat.notIgnoredUnitUnusedRead, stat.notIgnoredUnitWrite, stat.notIgnoredUnitSyscall);
		
		printf("\nTotalBytes %ld\nnotIgnoredUnitBytes %lld\n", ftell(fp), stat.notIgnoredUnitBytes);
		printf("allSyscallBytes %lld\nsyscallBytes %lld\nunimportantSyscallBytes %lld\n", stat.allSyscallBytes, stat.syscallBytes, stat.allSyscallBytes - stat.syscallBytes);
		printf("unusedReadBytes %lld\nunusedWriteBytes %lld\nunusedSyscallBytes %lld\ndupReadBytes %lld\ndupWriteBytes %lld\nignoredUnitBytes %lld\n", stat.unusedReadBytes, stat.unusedWriteBytes, stat.unusedSyscallBytes, stat.dupReadBytes, stat.dupWriteBytes, stat.ignoredUnitBytes);
		printf("outSyscallBytes %lld\n", stat.outSyscallBytes);
		printf("\nmax_buf_size %ld\nmax_thread %ld\n", max_buf_size, max_thread);

		long numProcess = 0;
		long numMemTable = 0;
		std::map<long, UnitDetail>::iterator rit;
		for(rit = unit.begin(); rit != unit.end(); rit++)
		{
				int rsize = rit->second.addr_all.size();
				if(rsize > 0) numProcess++;
				numMemTable+=rsize;
		}
		printf("\nnumProcess %ld\nnumMemTable %ld\n", numProcess, numMemTable);
}
