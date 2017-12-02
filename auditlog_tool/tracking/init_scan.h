#ifndef UBSI_INIT_SCAN
#define UBSI_INIT_SCAN

int init_scan(const char *name);
int save_init_tables(const char *name);
int load_init_tables(const char *name);

extern long num_syscall;
#endif
