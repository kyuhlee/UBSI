#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//#include <map>
//#include <set>
#include <assert.h>
#include "uthash.h"

#define UENTRY 0xffffff9c
#define UEXIT 0xffffff9b
#define MREAD1 0xffffff38
#define MREAD2 0xffffff37
#define MWRITE1 0xfffffed4
#define MWRITE2 0xfffffed3

typedef int bool;
#define true 1
#define false 0

typedef struct thread_unit_t {
		int tid;
		int unitid;
} thread_unit_t;

typedef struct link_unit_t {
		thread_unit_t id;
		UT_hash_handle hh;
} link_unit_t;

typedef struct mem_proc_t {
		long int addr;
		int tid;				// last written tid
		int unitid;	// last written unit
		UT_hash_handle hh;
} mem_proc_t;

typedef struct mem_unit_t {
		long int addr;
		//int isWritten;
		UT_hash_handle hh;
} mem_unit_t;

typedef struct unit_table_t {
		int tid;
		int pid;
		int unitid;
		bool valid; // is valid unit?
		long int r_addr;
		long int w_addr;
		link_unit_t *link_unit;
		mem_proc_t *mem_proc;
		mem_unit_t *mem_unit; // mem_write_record in the unit
		UT_hash_handle hh;
} unit_table_t;

unit_table_t *unit_table;
FILE *out_fp;

void emit_log(unit_table_t *ut, char* buf)
{
		buf[strlen(buf)-2] = '\0';
		fprintf(out_fp, "%s unit=%d tid=%d\n",buf, ut->unitid, ut->tid);
}

void delete_unit_hash(link_unit_t *hash_unit, mem_unit_t *hash_mem)
{
	//	HASH_CLEAR(hh, hash_unit);
	//	HASH_CLEAR(hh, hash_mem);
		
		link_unit_t *tmp_unit, *cur_unit;
		mem_unit_t *tmp_mem, *cur_mem;
		HASH_ITER(hh, hash_unit, cur_unit, tmp_unit) {
				if(hash_unit != cur_unit) 
						HASH_DEL(hash_unit, cur_unit); 
				if(cur_unit) free(cur_unit);  
		}
		//if(hash_unit) free(hash_unit);

		HASH_ITER(hh, hash_mem, cur_mem, tmp_mem) {
				if(hash_mem != cur_mem) 
						HASH_DEL(hash_mem, cur_mem); 
				if(cur_mem) free(cur_mem);  
		}
		//if(hash_mem) free(hash_mem);

}

void delete_proc_hash(mem_proc_t *mem_proc)
{
		//HASH_CLEAR(hh, mem_proc);
		
		mem_proc_t *tmp_mem, *cur_mem;
		HASH_ITER(hh, mem_proc, cur_mem, tmp_mem) {
				if(mem_proc != cur_mem) 
						HASH_DEL(mem_proc, cur_mem); 
				if(cur_mem) free(cur_mem);  
		}
		//if(mem_proc) free(mem_proc);
}

void unit_end(unit_table_t *unit)
{
		struct link_unit_t *ut;
		char buf[10240];

		if(unit->valid == true || HASH_COUNT(unit->link_unit) > 1) {
				bzero(buf, 10240);
				// emit linked unit lists;
				if(unit->link_unit != NULL) {
						sprintf(buf, "TYPE=unit unit=\"");
						for(ut=unit->link_unit; ut != NULL; ut=ut->hh.next) {
								sprintf(buf+strlen(buf), "%d-%d,", ut->id.tid, ut->id.unitid);
						}
						sprintf(buf+strlen(buf), "\"\n");
						emit_log(unit, buf);
				}
		}

		delete_unit_hash(unit->link_unit, unit->mem_unit);
		//if(unit->link_unit != NULL) printf("link_unit is not NULL %p\n", unit->link_unit);
		unit->link_unit = NULL;
		unit->mem_unit = NULL;
		unit->valid = false;
		unit->r_addr = 0;
		unit->w_addr = 0;
		unit->unitid++;
}

void proc_end(unit_table_t *unit)
{
		unit_end(unit);
		delete_proc_hash(unit->mem_proc);
		unit->mem_proc = NULL;
}

void proc_group_end(unit_table_t *unit)
{
		int pid = unit->pid;
		unit_table_t *pt;

		if(pid != unit->tid) {
				HASH_FIND_INT(unit_table, &pid, pt);
				proc_end(pt);
		}

		proc_end(unit);
}

void flush_all_unit()
{
		unit_table_t *tmp_unit, *cur_unit;
		HASH_ITER(hh, unit_table, cur_unit, tmp_unit) {
				unit_end(cur_unit);
		}
}

bool is_selected_syscall(int S, bool succ)
{
		//return true;
		if(!succ) 
				return false;
		
		switch(S) {
				case 0: case 19: case 1: case 20: case 44: case 45: case 46: case 47: case 86: case 88: case 56: case 57: case 58:
				case 59: case 2: case 85: case 257: case 259: case 133: case 32: case 33: case 292: case 49: case 43: case 288:
				case 42: case 82: case 105: case 113: case 90: case 22: case 293: case 76: case 77: case 40: case 87: case 263:
				return true;
		}
		return false;
}

void mem_write(unit_table_t *ut, long int addr)
{
		// check dup_write
		mem_unit_t *umt;
		HASH_FIND(hh, ut->mem_unit, &addr, sizeof(long int), umt);

		if(umt != NULL) return;
		
		// not duplicated write
		umt = (mem_unit_t*) malloc(sizeof(mem_unit_t));
		umt->addr = addr;
//		umt->isWritten = 1;
		HASH_ADD(hh, ut->mem_unit, addr, sizeof(long int),  umt);

		// add it into process memory map
		int pid = ut->pid;
		unit_table_t *pt;
		if(pid == ut->tid) pt = ut;
		else {
				HASH_FIND_INT(unit_table, &pid, pt);
				if(pt == NULL) {
						assert(1);
				}
		}

		mem_proc_t *pmt;
		HASH_FIND(hh, pt->mem_proc, &addr, sizeof(long int), pmt);
		if(pmt == NULL) {
				pmt = (mem_proc_t*) malloc(sizeof(mem_proc_t));
				pmt->addr = addr;
				pmt->tid = ut->tid;
				pmt->unitid = ut->unitid;
				HASH_ADD(hh, pt->mem_proc, addr, sizeof(long int),  pmt);
		} else {
				pmt->tid = ut->tid;
				pmt->unitid = ut->unitid;
		}
}

void mem_read(unit_table_t *ut, long int addr)
{
		int pid = ut->pid;
		unit_table_t *pt;
		if(pid == ut->tid) pt = ut;
		else {
				HASH_FIND_INT(unit_table, &pid, pt);
				if(pt == NULL) {
						assert(1);
				}
		}

		mem_proc_t *pmt;
		HASH_FIND(hh, pt->mem_proc, &addr, sizeof(long int), pmt);
		if(pmt == NULL) return;

		if((pmt->tid != ut->tid) || (pmt->unitid != ut->unitid))
		{
				link_unit_t *lt;
				thread_unit_t lid;
				lid.tid = pmt->tid;
				lid.unitid = pmt->unitid;
				HASH_FIND(hh, ut->link_unit, &lid, sizeof(thread_unit_t), lt);
				if(lt == NULL) {
				//		printf("lt is null, now add hash link, ");
						lt = (link_unit_t*) malloc(sizeof(link_unit_t));
						lt->id.tid = pmt->tid;
						lt->id.unitid = pmt->unitid;
						HASH_ADD(hh, ut->link_unit, id, sizeof(thread_unit_t), lt);
				//		if(ut->link_unit == NULL) printf("It is NULL!\n");
					//	else printf("correctly inserted\n");
				}
		}
}

unit_table_t* add_unit(int tid, int pid, int unitid, bool valid)
{
		struct unit_table_t *ut;
		ut = malloc(sizeof(struct unit_table_t));
		ut->tid = tid;
		ut->pid = pid;
		ut->unitid = unitid;
		ut->valid = valid;
		ut->link_unit = NULL;
		ut->mem_proc = NULL;
		ut->mem_unit = NULL;
		HASH_ADD_INT(unit_table, tid, ut);
		return ut;
}

void set_pid(int tid, int pid)
{
		struct unit_table_t *ut;

		HASH_FIND_INT(unit_table, &tid, ut);  /* id already in the hash? */
		if (ut == NULL) {
				ut = add_unit(tid, pid, 0, 0);
		} else {
				ut->pid = pid;
		}
}

void UBSI_event(long tid, long a0, long a1, char *buf)
{
		int isNewUnit = 0;
		struct unit_table_t *ut;
		HASH_FIND_INT(unit_table, &tid, ut);
		
		if(ut == NULL) {
				isNewUnit = 1;
				ut = add_unit(tid, tid, 0, 0);
		}

		switch(a0) {
				case UENTRY: 
				case UEXIT: 
						// if the unit exist, finish the unit.
						if(isNewUnit == false)
						{
								unit_end(ut);
						}
						break;
				case MREAD1:
						ut->r_addr = a1;
						ut->r_addr = ut->r_addr << 32;
						break;
				case MREAD2:
						ut->r_addr += a1;
						mem_read(ut, ut->r_addr);
						break;
				case MWRITE1:
						ut->w_addr = a1;
						ut->w_addr = ut->w_addr << 32;
						break;
				case MWRITE2:
						ut->w_addr += a1;
						mem_write(ut, ut->w_addr);
						break;
		}
}

void non_UBSI_event(long tid, int sysno, bool succ, char *buf)
{
		char *ptr;
		long a2;
		long ret;

		bool isNewUnit = false;
		struct unit_table_t *ut;
		
		if(!is_selected_syscall(sysno, succ))  return;

		HASH_FIND_INT(unit_table, &tid, ut);
		
		if(ut == NULL) {
				isNewUnit = true;
				ut = add_unit(tid, tid, 0, 0);
		}
		
		//emit system calls.
		emit_log(ut, buf);
		
		if(succ == true && (sysno == 56 || sysno == 57 || sysno == 58)) // clone or fork
		{
				ptr = strstr(buf, " a2=");
				a2 = strtol(ptr+4, NULL, 16);

				
				if(a2 > 0) { // thread_creat event
						ptr = strstr(buf, " exit=");
						ret = strtol(ptr+6, NULL, 16);
						set_pid(ret, tid);
				}
		} else if(succ == true && ( sysno == 59 || sysno == 322 || sysno == 60 || sysno == 231)) { // execve, exit or exit_group
				if(sysno == 231) { // exit_group call
						// TODO: need to finish all thread in the process group
						proc_group_end(ut);
				}
				unit_end(ut);
				proc_end(ut);
		} else {
				ut->valid = true;
		}
}

void get_comm(char *buf, char *comm)
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

void syscall_handler(char *buf)
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
						UBSI_event(pid, a0, a1, buf);
						//printf("pid %d, a0 %x, a1 %x: %s\n", pid, a0, a1, buf);
				} else {
						non_UBSI_event(pid, sysno, succ, buf);
				}
		} else {
				non_UBSI_event(pid, sysno, succ, buf);
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

int buffering(char *buf)
{

}

int main(int argc, char **argv)
{
		FILE *fp;
		char buf[1048576], buf2[1048576];
		int i = 0;
		long fend, fcur, ftmp;
		char *ptr;
		long eid, teid;
		
		if(argc < 3 || (fp=fopen(argv[1], "r")) ==NULL || (out_fp=fopen(argv[2], "w")) == NULL) {
				printf("usage: ./a.out input output\n");
				return 0;
		}
		
		long max_buf = 0;
		long buf_size =0;
		long cur_buf_size = 0;
		int max_line = 0;
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
				
				buf_size = strlen(buf);
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
						if(teid == eid) {
								if(strncmp(buf2, "type=UNKNOWN",12) != 0) {
										strcat(buf, buf2);
										cur_buf_size = strlen(buf2);
										buf_size += cur_buf_size;
										if(max_buf < buf_size) {
												max_buf = buf_size;
										}
								}
						}
				}
				
				syscall_handler(buf);
				fseek(fp, ftmp, SEEK_SET);
				fcur = ftmp;
				
				if(i++ > 10000) {
						loadBar(fcur, fend, 10, 50);
						i = 0;
			 }
				
				fcur = ftell(fp);
				fgets(buf, 1048576, fp);
		}
		flush_all_unit();
		fclose(fp);
		fclose(out_fp);
		printf("max_buf = %ld in line %d\n", max_buf, max_line);
}
