#ifndef UBSI_TABLES
#define UBSI_TABLES

#include "uthash.h"
#include "utlist.h"
#include "utils.h"
#include <set>
#include <map>
#include <vector>

typedef struct cluster_el_t {
		int pid;
		int clusterid; // if clusterid == -1, the whole process is tainted.
} cluster_el_t;

typedef struct tainted_cluster_t {
		cluster_el_t id;
		string path;
		UT_hash_handle hh;
} tainted_cluster_t;

typedef struct inode_t {
		long inode;
		long created_eid;
} inode_t;

typedef struct tainted_inode_t {
		inode_t inode;
		long created_eid;
		string name;
		UT_hash_handle hh;
} tainted_inode_t;

typedef struct thread_process_t {
		int tid;
		int pid;
		UT_hash_handle hh;
} thread_process_t;

typedef struct unit_el_t {
		int tid;
		int unitid;
} unit_el_t;

typedef struct unit_list_t {
		unit_el_t id;
		struct unit_list_t *prev;
		struct unit_list_t *next;
} unit_list_t;

typedef struct unit_cluster_t {
		int clusterid;
		unit_list_t *list;
		UT_hash_handle hh;
} unit_cluster_t;

typedef struct unit_table_t {
		unit_el_t id;
		int clusterid;
		UT_hash_handle hh;
} unit_table_t;

typedef struct fd_el_t {
		long eid; // fd opened at this event id.
		bool is_socket;
		int num_path;
		bool is_pair;
		int paired_fd;
		bool is_pipe;
		int piped_fd;
		long inode[MAX_PATH];
		string cwd;
		string path[MAX_PATH];
		string pathtype[MAX_PATH];
		struct fd_el_t *prev;
		struct fd_el_t *next;
} fd_el_t;

typedef struct fd_table_t {
		int fd;
		fd_el_t *fd_el; // same fd can be opened multiple times.
		UT_hash_handle hh;
} fd_table_t;

typedef struct process_table_t {
		int pid;
		int next_cluster_id;
		unit_cluster_t *unit_cluster;
		unit_table_t *unit_table;
		fd_table_t *fd_table;
		UT_hash_handle hh;
} process_table_t;

typedef struct inode_el_t {
		long created_eid;
		long deleted_eid;
		string name;
		time_t created_time;
		unsigned int created_time_mil;
		time_t deleted_time;
		unsigned int deleted_time_mil;
		struct inode_el_t *prev;
		struct inode_el_t *next;
} inode_el_t;

typedef struct inode_table_t {
		long inode;
		vector<inode_el_t> list;
		UT_hash_handle hh;
} inode_table_t;

process_table_t *get_process_table(int pid);
string merge_path(fd_el_t *el);
unit_list_t *get_unit_list(int tid, int unitid);
fd_el_t *get_fd(process_table_t *pt, int fd, long eid);
int get_pid(int tid);
cluster_el_t get_cluster(int tid, int unitid);
void print_unit_cluster(int pid, unit_cluster_t* ut);
void print_all_unit_clusters(int pid);
void print_fd_list(int pid, fd_table_t *ft);
long check_inode_list(long user_inode, string *path);

inode_t find_inode(long inode, long eid);
bool is_tainted_unit(process_table_t *pt, int clusterid);
bool is_tainted_unit(process_table_t *pt, int tid, int unitid);
bool is_tainted_pid(int pid);
bool is_tainted_inode(long inode, long eid);
bool taint_unit(process_table_t *pt, int tid, int unitid, string path);
bool taint_unit(process_table_t *pt, int clusterid, string path);
bool taint_all_units_in_pid(int pid, string path);
bool taint_inode(long inode, long eid, string path);
void print_fp_table();
void generate_fp_table(FILE *fp);
void init_table();
string get_absolute_path(fd_el_t *fd_el, int num);
string get_absolute_path(string cwd, string path);
void insert_single_unit(process_table_t *pt, int tid, int unitid);
int taint_socket(string name);


void edge_proc_to_file(int tid, int unitid, long inode, long eid);
void edge_file_to_proc(int tid, int unitid, long inode, long eid);
void edge_proc_to_proc(int from_tid, int from_unitid, int to_pid);
void edge_proc_to_socket(int tid, int unitid, int socket);
void edge_socket_to_proc(int tid, int unitid, int socket);

extern thread_process_t *thread2process_table;
extern process_table_t *process_table;
extern long **fp_table; 
extern int fp_table_size;
extern long num_syscall;
extern long user_inode;
extern int user_pid;

extern tainted_cluster_t *tainted_cluster;
extern tainted_inode_t *tainted_inode;
extern set<int> tainted_pid; // at lease one cluster is tainted. Need to use for fork/clone..
extern map<string, int> tainted_socket;
extern set<string> edge_list; 


#endif
