#include "uthash.h"

#define SERVER_PATH     "/var/run/audispd_events"
#define BUFFER_LENGTH   10000
#define FALSE           0
#define TRUE		1


#define UENTRY 0xffffff9c // (kill(-100
#define UENTRY_ID 0xffffff9a // (kill (-102

#define UEXIT 0xffffff9b // (kill (-101
#define MREAD1 0xffffff38
#define MREAD2 0xffffff37
#define MWRITE1 0xfffffed4
#define MWRITE2 0xfffffed3
#define UDEP 0xfffffe70 // (kill (-400, dependent id)

#define true 1
#define false 0

#define MAX_SIGNO 50


// A struct to keep time as reported in audit log. Upto milliseconds.
// Doing it this way because double and long values don't seem to work with uthash in the structs where needed
typedef struct thread_time_t{
	int seconds;
	int milliseconds;
} thread_time_t;

typedef struct thread_unit_t {
		int tid;
		thread_time_t thread_time; // thread create time. seconds and milliseconds.
		int loopid; // loopid. in the output, we call this unitid.
		int iteration;
		double timestamp; // loop start time. Not iteration start.
		int count; // if two or more loops starts at the same timestamp. We use count to distinguish them.
} thread_unit_t;

typedef struct link_unit_t { // list of dependent units
		thread_unit_t id;
		UT_hash_handle hh;
} link_unit_t;

typedef struct mem_proc_t {
		long int addr;
		thread_unit_t last_written_unit;
		UT_hash_handle hh;
} mem_proc_t;

typedef struct mem_unit_t {
		long int addr;
		UT_hash_handle hh;
} mem_unit_t;

typedef struct thread_t {
		int tid; // pid in auditlog which is actually thread_id.
		thread_time_t thread_time; // thread create time. seconds and milliseconds.
} thread_t;

typedef struct unit_id_map_t {
		int unitid;
		thread_unit_t thread_unit;
		UT_hash_handle hh;
} unit_id_map_t;

typedef struct fd_t {
		// KYU: unit integration
		enum fd_type
		{
				file,
				socket,
				pipe
		};
		long fd;
		char name[1024]; // filename or local sock
		int inode;
		fd_type type; // 1: normal file, 2: socket, 3:pipe
		int isImportant;
		UT_hash_handle hh;
} fd_t;

typedef struct unit_table_t {
		thread_t thread;
//		int tid; // pid in auditlog which is actually thread_id.
		int pid; // process id.  (main thread id)
		thread_unit_t cur_unit;
		bool valid; // is valid unit?
		long int r_addr;
		long int w_addr;
		link_unit_t *link_unit;
		mem_proc_t *mem_proc;
		mem_unit_t *mem_unit; // mem_write_record in the unit
		int unitid;
		int merge_count;
		unit_id_map_t *unit_id_map;
		char proc[1024];
		bool signal_handler[MAX_SIGNO];
		UT_hash_handle hh;
		/* KYU: test for unit integration */
		int new_dep;
		int num_proc_syscall; // clone, exec, kill, 
		int num_io_syscall; // file/socket read and write
		int num_syscall;
		fd_t *fd;
		/* KYU: unit integration */
		/* for OQL support */
		char comm[1024];
		char exe[1024];
		int uid;
		int euid;
		int gid;
		int ppid;
		/* OQL support */
} unit_table_t;

typedef struct event_buf_t {
		int id;
		int items;
		int items_read;
		int waiting;
		int event_byte;
		char *event;
		UT_hash_handle hh;
} event_buf_t;

// Equality check is done using only tid, unitid, and iteration
typedef struct iteration_count_t{
	int tid;
	int unitid;
	int iteration;
	int count;
} iteration_count_t;

typedef struct thread_group_leader_t {
		thread_t thread;
		thread_t leader;
		UT_hash_handle hh;
} thread_group_leader_t;

// child --> thread_group_leader
typedef struct thread_hash_t{
		thread_t thread;
		UT_hash_handle hh;
} thread_hash_t;

/* thread_group_leader --> list of child threads
// sys_exit:  clear all child threads data only if I am the thread leader
// sys_exit_group: find thread leader and clear all child.
*/
typedef struct thread_group_t{
		thread_t leader;
		thread_hash_t *threads;
		UT_hash_handle hh;
} thread_group_t;


extern int UBSIAnalysis;

string filename_open_tmp(char *buf, int *inode);
void CSV_execve(unit_table_t *ut, char *buf);
void CSV_file_open(unit_table_t *ut, char *buf);
void CSV_file_access_by_name(unit_table_t *ut, char *buf, int sysno);
void CSV_access_by_fd(unit_table_t *ut, char *buf, int fd, char* name, int inode);
void CSV_default(unit_table_t *ut, char *buf);
void CSV_socket(unit_table_t *ut, char *buf, const char *sockaddr, int fd);
void CSV_socket2(unit_table_t *ut, char *buf, const char *sockaddr, int fd, const char *remote);
void CSV_pipe(unit_table_t *ut, char *buf, int fd0, int fd1);
void CSV_link(unit_table_t *ut, char *buf, int sysno, int fd0, int fd1);
void CSV_unlink(unit_table_t *ut, char *buf);
void CSV_rename(unit_table_t *ut, char *buf, int sysno, int fd0, int fd1);
void CSV_sendfile(unit_table_t *ut, char *buf, int in_fd, char *in_name, int in_inode, int out_fd, bool out_socket, char *out_name, int out_inode);
void CSV_netio(unit_table_t *ut, char *buf, int fd, const char* fd_name, const char *local_addr, const char *remote_addr);
void CSV_UBSI(unit_table_t *ut, char *buf, const char *evtType, const char *depTid, const char *depUnitid);
