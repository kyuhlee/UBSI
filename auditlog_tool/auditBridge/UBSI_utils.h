#ifndef UBSI_UTILS
#define UBSI_UTILS

#include <string>

#define MAX_PATH 10
//#define DEBUGBT
//#define DEBUGTAINT
//#define DEBUGNOW 1
//#define DEBUG 1

#ifdef DEBUGBT
		#define DEBUGANY
		#define debugbt(M, ...) fprintf(stderr, "DEBUG %s:%d: " M, __FILE__, __LINE__, ##__VA_ARGS__)
#else
		#define debugbt(M, ...)
#endif

#ifdef DEBUGTAINT
		#define DEBUGANY
		#define debugtaint(M, ...) fprintf(stderr, "DEBUG %s:%d: " M, __FILE__, __LINE__, ##__VA_ARGS__)
#else
		#define debugtaint(M, ...)
#endif

#ifdef DEBUGNOW
		#define DEBUGANY
		#define debugnow(M, ...) fprintf(stderr, "DEBUG %s:%d: " M, __FILE__, __LINE__, ##__VA_ARGS__)
#else
		#define debugnow(M, ...)
#endif

#ifdef DEBUG
		#define DEBUGANY
#define debug(M, ...) fprintf(stderr, "DEBUG %s:%d: " M, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define debug(M, ...)
#endif


using namespace std;

void loadBar(long x, long n, int r, int w);
string convert_time(time_t t, unsigned int mil);
int extract_time(char *s, time_t *t, unsigned int *mil);
string extract_sockaddr(char *ss, const char *needle);
string extract_string(char *s, const char *needlee);
int extract_int(char *s, const char *needle, int *store);
int extract_hex_int(char *s, const char *needle, int *store);
int extract_long(char *s, const char *needle, long *store);
int extract_hex_long(char *s, const char *needle, long *store);
int get_fd(int sysno, char *buf);


void get_comm(char *buf, char *comm);
bool get_succ(char *buf);
bool is_read(int sysno);
bool is_write(int sysno);
bool is_socket(int sysno);
bool is_file_create(int sysno);
bool is_file_delete(int sysno);
bool is_file_rename(int sysno);
bool is_fork_or_clone(int sysno);
bool is_exec(int sysno);

void get_sockaddr(const char *val, char *family_t, char *addr_t, char *port_t);
#endif
