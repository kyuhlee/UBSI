#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include "libaudit.h"
#include "auparse.h"

/* Global Data */
static volatile int stop = 0;
static volatile int hup = 0;
static auparse_state_t *au = NULL;

/* Local declarations */
static void handle_event(auparse_state_t *au,
				auparse_cb_event_t cb_event_type, void *user_data);

// KYU modification start
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

FILE *log_fd;

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

int emit_log(unit_table_t *ut, char* buf)
{
		buf[strlen(buf)-1] = '\0';
		int rc = fprintf(stdout, "%s unitid=%d\n",buf, ut->unitid);
		//int rc = fprintf(log_fd, "%s unitid=%d\n",buf, ut->unitid);

		fflush(log_fd);
		return rc;
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
						sprintf(buf, "type=unit list=\"");
						for(ut=unit->link_unit; ut != NULL; ut=ut->hh.next) {
								sprintf(buf+strlen(buf), "%d-%d,", ut->id.tid, ut->id.unitid);
						}
						sprintf(buf+strlen(buf), "\" tid=%d \n", unit->tid);
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
		if(S == 60 || S == 231 || S == 42)  return true;

		if(!succ) 
		{	
				return false;
		}
		
		switch(S) {
				case 0: case 19: case 1: case 20: case 44: case 45: case 46: case 47: case 86: case 88: 
				case 56: case 57: case 58: case 59: case 2: case 85: case 257: case 259: case 133: case 32: 
				case 33: case 292: case 49: case 43: case 288: case 42: case 82: case 105: case 113: case 90:
				case 22: case 293: case 76: case 77: case 40: case 87: case 263: case 62: case 9: case 10:
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
		int ppid;

		HASH_FIND_INT(unit_table, &pid, ut);  /* looking for parent thread's pid */
		if(ut == NULL) ppid = pid;
		else ppid = ut->pid;

		ut = NULL;

		HASH_FIND_INT(unit_table, &tid, ut);  /* id already in the hash? */
		if (ut == NULL) {
				ut = add_unit(tid, ppid, 0, 0); 
		} else {
				ut->pid = ppid;
		}

}

void UBSI_event(long tid, long a0, long a1)//, char *buf)
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

		//bool isNewUnit = false;
		struct unit_table_t *ut;
		
		if(!is_selected_syscall(sysno, succ))  return;

		HASH_FIND_INT(unit_table, &tid, ut);
		
		if(ut == NULL) {
//				isNewUnit = true;
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
						ret = strtol(ptr+6, NULL, 10);
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
	//	printf("success = %s: %s", succ, buf);
		if(strncmp(succ, "yes", 3) == 0) {
				return true;
		}
	return false;
}

void syscall_handler(char *buf)
{
		char *ptr;
		int sysno;
		long a0, a1, pid;
		//char comm[64];
		bool succ = false;
		
		//fprintf(log_fd, "syscall_handler: %s\n", buf);
		//fflush(log_fd);

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
		//else printf("succ=YES!, %s\n", buf);
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
						//UBSI_event(pid, a0, a1, buf);
						//printf("pid %d, a0 %x, a1 %x: %s\n", pid, a0, a1, buf);
				} else {
						non_UBSI_event(pid, sysno, succ, buf);
				}
		} else {
				non_UBSI_event(pid, sysno, succ, buf);
		}
}

int buffering(const char *buf, int execute)
{
		//static long last_eid = 0;
		static char stag_buf[1048576];
		//long eid;
		char *ptr;

		if(execute) {
				//if(strncmp(stag_buf, "type=SYSCALL",12) == 0 ) {
				ptr = strstr(stag_buf, "type=SYSCALL");
				if(ptr != NULL) {
						syscall_handler(stag_buf);
				}
				bzero(stag_buf, 1048576);
		} else {
				if(strncmp(buf, "type=UNKNOWN",12) == 0 || strncmp(buf, "type=PROCTITLE",14) == 0 ) 
						return 0;
				strcat(stag_buf, buf);
				strcat(stag_buf, "\n");
		}
}

// KYU Modification end



/*
	* SIGTERM handler
	*/
static void term_handler( int sig )
{
		stop = 1;
}

/*
	* SIGHUP handler: re-read config
	*/
static void hup_handler( int sig )
{
		hup = 1;
}

static void reload_config(void)
{
		hup = 0;
}

int main(int argc, char *argv[])
{
		char tmp[MAX_AUDIT_MESSAGE_LENGTH+1];
		struct sigaction sa;

		/* Register sighandlers */
		sa.sa_flags = 0;
		sigemptyset(&sa.sa_mask);
		/* Set handler for the ones we care about */
		sa.sa_handler = term_handler;
		sigaction(SIGTERM, &sa, NULL);
		sa.sa_handler = hup_handler;
		sigaction(SIGHUP, &sa, NULL);

		//printf("audisp-UBSI started\n");
		log_fd = fopen("/tmp/log.tmp", "w");
		
		if(log_fd == NULL) return 0;
		/* Initialize the auparse library */
		printf("auspid-UBSI started.\n");
		fprintf(log_fd, "auspid-UBSI started.\n");
		fflush(log_fd);

		au = auparse_init(AUSOURCE_FEED, 0);
		if (au == NULL) {
				printf("audisp-UBIS is exiting due to auparse init errors");
				fprintf(log_fd, "audisp-UBIS is exiting due to auparse init errors");
				return -1;
		}
		auparse_add_callback(au, handle_event, NULL, NULL);
		do {
				/* Load configuration */
				if (hup) {
						reload_config();
				}
				/* Now the event loop */
				if(fgets_unlocked(tmp, MAX_AUDIT_MESSAGE_LENGTH, stdin) &&
								hup==0 && stop==0) {
						auparse_feed(au, tmp, strnlen(tmp,
												MAX_AUDIT_MESSAGE_LENGTH));
				}
				auparse_flush_feed(au);
				if (feof(stdin))
						break;

		} while (stop == 0);


		/* Flush any accumulated events from queue */
		auparse_flush_feed(au);
		auparse_destroy(au);

		fclose(log_fd);
/*		if (stop)
				printf("audisp-UBIS is exiting on stop request\n");
		else
				printf("audisp-UBIS is exiting on stdin EOF\n");
*/
		return 0;
}

/* This function receives a single complete event at a time from the auparse
	* library. This is where the main analysis code would be added. */
static void handle_event(auparse_state_t *au,
				auparse_cb_event_t cb_event_type, void *user_data)
{
		int type, num=0;
		

		do {
				buffering(auparse_get_record_text(au), 0);
		} while(auparse_next_record(au) > 0);
		buffering(NULL, 1);
		return;

		if (cb_event_type != AUPARSE_CB_EVENT_READY)
				return;
}

