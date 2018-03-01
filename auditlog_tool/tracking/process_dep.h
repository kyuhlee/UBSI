#ifndef __UBSI_dep_h
#define __UBSI_dep_h

#include "uthash.h"

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

typedef struct unit_t{
		thread_unit_t unit;
		int clusterid;
		UT_hash_handle hh;
} unit_t;

typedef struct unit_clusterid_t{
		int clusterid;
		int newid;
		UT_hash_handle hh;
} unit_clusterid_t;

int get_unitid(thread_unit_t *unit);
int scan_dep_file(const char *log_name);
int scan_unit(char *ptr, thread_unit_t *unit);
void print_unit_table(FILE *fp, const char *table);

#endif
