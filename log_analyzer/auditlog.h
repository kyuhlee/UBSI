
#include <set>
#include <map>
#include <stack>
#include <queue>
#include <string>

#define MAX_PATH 10
using namespace std;

//#define IGNORE_SRC 26
//#define KYU_TEST
#define INT long
//#define IGNORE_READONLY_FILE
#define IGNORE_WRITEONLY_FILE
#define IGNORE_LIB_CONF
#define BT_IGNORE_WRITE
#define NDEBUG
#define NDEBUG_CORE

#ifdef NDEBUG
#define debug(M, ...)
#else
#define debug(M, ...) fprintf(stderr, "DEBUG %s:%d: " M, __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#ifdef NDEBUG_CORE
#define debug_core(M, ...)
#else
#define debug_core(M, ...) fprintf(stderr, "%s:%d: " M, __FILE__, __LINE__, ##__VA_ARGS__)
#endif

//#define WITHOUT_UNIT 1
// interested filename and pid.
typedef struct {
		map<string, set<INT> > filename;
		map<INT, set<INT> > inode;
} DepList;

typedef struct {
		map<INT, string> filename;
		set<string> socketRead;
		set<INT> fileWrite; // <from_n>
//		set<string> fileRead;
} TempListUnit;

typedef struct {
		map<INT, TempListUnit> unitList;
} TempList;

enum graph_type {
		G_init = 1,
		G_fork,
		G_read,
		G_write,
		G_receive,
		G_send,
		G_exit,
};

typedef struct {
		graph_type type;
		string path;
		string time;
		INT uid;
		INT auid;
		INT unitid;
		INT num;
} GraphList;


enum syscall_num {
		SYS_read = 0,
		SYS_write = 1,
		SYS_open = 2,
		SYS_close = 3,
		SYS_mmap = 9,
		SYS_pread = 17,
		SYS_pwrite = 18,
		SYS_readv = 19,
		SYS_writev = 20,
		SYS_pipe = 22,
  SYS_dup = 32,
  SYS_dup2 = 33,
		SYS_socket = 41,
		SYS_connect = 42,
		SYS_accept = 43,
		SYS_sendto = 44,
		SYS_recvfrom = 45,
		SYS_sendmsg = 46,
		SYS_recvmsg = 47,
		SYS_clone = 56,
		SYS_fork = 57,
		SYS_vfork = 58,
		SYS_execve = 59,
		SYS_kill = 62,
		SYS_rename = 82,
		SYS_link = 86,
		SYS_unlink = 87,
		SYS_unlinkat = 263,
		SYS_accept4 = 288,
		SYS_dup3 = 292,
		SYS_pipe2 = 293,
		SYS_preadv = 295,
		SYS_pwritev = 296,
};

enum entry_type {
		UNDEFINED = 0,
		DAEMON_START,
		USER_AUTH,
		USER_ACCT,
		CRED_ACQ,
		USER_END, //5
		USER_LOGIN,
		USER_START,
		USER_ROLE_CHANGE,
		CRED_DISP,
		LOGIN,
		SYSCALL, //11
		INCLUDEDFROMTHIS,
		SOCKADDR,
		CWD,
		PATH,
		EXECVE,
		FD_PAIR,
		ETC,
};

typedef struct {
		string name;
		INT inode;
		INT mode;
		bool isDir;
} Path;

typedef struct {
		string hostname;
		string ext;
		string terminal;
		string comm;
		//string path[MAX_PATH]; //need to remove.
		string fileName[2];
		string dirName[2];
		INT fileNameNum;
		INT dirNameNum;
		string cwd;
		string exe;
		string saddr;
		string time;
		INT fd_pair[2];

		INT path_size;
		entry_type type;
		time_t sec;
		unsigned INT mili;
		INT log_num;
		INT res;
		INT uid;
		INT auid;
		INT pid;
		INT unitid;
		INT ppid;
		INT sysnum;
		INT exit;
		INT inode;
		INT extra_inodes[10];
		INT num_path;  // in some cases, the log has multiple paths. 
		INT arg[4];
		bool isWrite;
		bool success;
} LogEntry;


typedef struct {
		string comm;
		string time;
		INT uid;
		INT auid;
} ForkChild; // This is necessary when the program fork but not exec

extern map<INT, ForkChild> forkChild;
extern set<INT> taintedUnitList;
extern map<INT, TempList> tempList;
extern DepList tainted;
extern set<INT> taintedPid;
extern FILE *log_fd, *new_log_fd;
extern LogEntry logentry;
extern bool rootAccessDetect;
extern map<INT, INT> unitId;
extern bool is_forward_search;
extern char auditlog_name[256];
extern char parse_sock[256];
extern map<INT, map<INT,INT> > dup_map; // <pid, <newfd, oldfd> >

const char *get_syscall_name(INT num);
void log_clean();
void print_log_entry(FILE *fp);
bool is_dir(string str);
void	insert_temp_list_fileWrite(INT pid, INT from_n);
void insert_temp_fileread(string path);
INT process_single_log(bool scan);
void open_log();
INT process_log(INT num);
INT insert_inode(INT inode);
void checkUserInput(string name);

//backward_search
void reverse_log(void);
extern set<INT> user_inode;
extern string user_file_name;
extern INT max_log_num;

//graph
void graph_init();
void graph_fini();
string graph_add_processNode(INT pid, string comman);
string graph_add_fileNode(string name);
string graph_add_socketNode(string name);
void graph_add_edge(string from, string  to);

//unit
extern map<INT,INT> unitMax;
extern map<INT, set<INT> > unitMap;
INT get_dep_units(INT pid, INT unitid);
bool is_unit_begin_backward();
bool is_unit_begin_forward();
bool is_unit_end();
void unit_detect_mem(INT spid, INT pid, INT unitid);
void print_dep_units();
void unit_id_reset();

//init scan
INT init_scan(bool is_forward_search);
INT init_scan_test(bool is_forward_search);
string fd_to_name(INT pid, INT fd, INT num, bool *isSocket);
INT fd_to_inode(INT pid, INT fd, INT num, bool *isSocket);
INT get_parent_thread_id(INT pid);
INT scan_path_process(Path path, INT num, string cur_dir);
string inode_to_name(INT inode, INT num);

// tainted_track
bool is_tainted_proc(INT pid, INT unitid);
INT insert_tainted_proc(INT pid, INT unitid);
void insert_tainted_proc_list(INT pid, INT unitid);
bool is_tainted_inode(INT inode, bool isWrite);
bool is_tainted_pid(INT pid);
INT insert_tainted_inode2(INT inode, bool isWrite);
void remove_tainted_inode(INT inode);


void insert_dup(INT spid, INT oldfd, INT newfd);
INT find_dup_fd(INT spid, INT fd) ;
void kyu_print_mem_access();
void inherit_file_table(INT old_spid, INT new_spid);
