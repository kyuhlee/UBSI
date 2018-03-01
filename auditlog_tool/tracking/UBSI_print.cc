#include <stdio.h>
#include <unistd.h>
#include "init_scan.h"
#include "utils.h"
#include "tables.h"
#include "graph.h"

#define false 0
#define true 1

FILE *out_fp;
FILE *out_dep_fp;

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

// Reads timestamp from audit record and then sets the seconds and milliseconds to the thread_time struct ref passed
void set_thread_time(char *buf, thread_time_t* thread_time)
{
		char *ptr;
		ptr = strstr(buf, "(");
		assert(ptr);
		
		sscanf(ptr+1, "%d.%d", &(thread_time->seconds), &(thread_time->milliseconds));
		//double time = get_timestamp(buf);
		//thread_time->seconds = (int)time;
		//thread_time->milliseconds = (int)((time - thread_time->seconds) * 1000);
}

int scan_unit(char *ptr, thread_unit_t *unit)
{
		sscanf(ptr, "(pid=%d thread_time=%d.%d unitid=%d iteration=%d time=%lf count=%d) ", 
		  &(unit->tid), &(unit->thread_time.seconds), &(unit->thread_time.milliseconds), 
				&(unit->loopid), &(unit->iteration), &(unit->timestamp), &(unit->count));
}

void print_unit(thread_unit_t *unit, FILE *fp)
{
			fprintf(fp, "(pid=%d thread_time=%d.%d unitid=%d iteration=%d time=%.3lf count=%d) ",
		  unit->tid, unit->thread_time.seconds, unit->thread_time.milliseconds, 
				unit->loopid, unit->iteration, unit->timestamp, unit->count);
}

void write_handler(int sysno, char *buf)
{
		int fd, tid, pid, unitid;
		long eid;
		string exe;
		process_table_t *pt;
		thread_unit_t uid;
		char *ptr;

		fd = get_fd(sysno, buf);
		extract_long(buf, ":", 1, &eid);
		extract_int(buf, " pid=", 5, &tid);
		extract_int(buf, " unitid=", 8, &unitid);

		ptr = strstr(buf, " unit=(");
		if(ptr == NULL) {
				fprintf(stderr, "PTR NULL: %s\n", buf);
		}
		assert(ptr);
		
		scan_unit(ptr+6, &uid);
#ifdef WITHOUT_UNIT
		unitid = -1;
#endif
		pid = get_pid(tid);

		pt = get_process_table(pid);

		//if(is_tainted_unit(pt, tid, unitid) == false) return;

		fd_el_t *fd_el;
		fd_el = get_fd(pt, fd, eid);

		if(fd_el == NULL || fd_el->num_path == 0) {
				debug("pid %d, eid %ld, fd %d does not exist\n", pid, eid, fd);
				//fprintf(out_fp, "UBSI_PATH: empty: pid %d, eid %ld, fd %d does not exist\n", pid, eid, fd);
				return;
		}
		
		fprintf(out_fp, "UBSI_PATH: WRITE unit=");
		print_unit(&uid, out_fp);
		fprintf(out_fp,  "fd %d (sysno %d, eid %ld, tid %d (pid %d)): inode %ld, path:%s, pathtype: %s\n",
						fd, sysno, eid, tid, pid, fd_el->inode[fd_el->num_path-1], 
						get_absolute_path(fd_el, fd_el->num_path-1).c_str(), fd_el->pathtype[fd_el->num_path-1].c_str());
}

void read_handler(int sysno, char *buf)
{
		int fd, tid, pid, unitid;
		long eid;
		string exe;
		thread_unit_t uid;
		process_table_t *pt;
		char *ptr;

		extract_int(buf, " pid=", 5, &tid);
		extract_int(buf, " unitid=", 8, &unitid);

		ptr = strstr(buf, " unit=(");
		if(ptr == NULL) {
				fprintf(stderr, "PTR NULL: %s\n", buf);
		}
		assert(ptr);
		
		scan_unit(ptr+6, &uid);

#ifdef WITHOUT_UNIT
		unitid = -1;
#endif

		pid = get_pid(tid);
		pt = get_process_table(pid);

		if(pt == NULL) {
				printf("WARNING: PT is NULL: buf=%s\n", buf);
				return;
		}

		fd = get_fd(sysno, buf);
		
		if(fd < 3) return;
		extract_long(buf, ":", 1, &eid);

		fd_el_t *fd_el;
		fd_el = get_fd(pt, fd, eid);

		if(fd_el == NULL || fd_el->num_path == 0) {
				//exe = extract_string(buf, " exe=", 5);
				//fprintf(out_fp, "tid %d, pid %d(%s), eid %ld, fd %d does not exist\n", tid, pid, exe.c_str(), eid, fd);
				return;
		}
		fprintf(out_fp, "UBSI_PATH: READ unit=");
		print_unit(&uid, out_fp);
		fprintf(out_fp,  "fd %d (sysno %d, eid %ld, tid %d (pid %d)): inode %ld, path:%s, pathtype: %s\n",
						fd, sysno, eid, tid, pid, fd_el->inode[fd_el->num_path-1], 
						get_absolute_path(fd_el, fd_el->num_path-1).c_str(), fd_el->pathtype[fd_el->num_path-1].c_str());

		/*		if(fd_el->is_socket == false && is_tainted_inode(fd_el->inode[fd_el->num_path-1], eid)) { // only check the last path..
						exe = extract_string(buf, " exe=", 5);
						edge_file_to_proc(tid, unitid, fd_el->inode[fd_el->num_path-1], eid);
						if(taint_unit(pt, tid, unitid, exe)) {
						debugbt("taint unit (tid %d, unitid %d, exe %s): read (sysno %d, eid %ld) (# path %d): inode %ld, path:%s, pathtype: %s\n", 
						tid, unitid, exe.c_str(),
						sysno, eid, fd_el->num_path, fd_el->inode[fd_el->num_path-1], 
						get_absolute_path(fd_el, fd_el->num_path-1).c_str(), 
						fd_el->pathtype[fd_el->num_path-1].c_str());
						}
						}
			*/
}

void file_create_handler(int sysno, char *buf)
{

}

void fork_handler(int sysno, char *buf)
{
		long eid;
		int ret;
		thread_unit_t uid;
		thread_unit_t child;
		char *ptr;
		
 	extract_int(buf, " exit=", 6, &ret); 
		extract_long(buf, ":", 1, &eid);

		ptr = strstr(buf, " unit=(");
		if(ptr == NULL) {
				fprintf(stderr, "PTR NULL: %s\n", buf);
		}
		assert(ptr);
		
		scan_unit(ptr+6, &uid);

		set_thread_time(buf, &(child.thread_time));
		child.tid = ret;
		child.loopid = 0;
		child.iteration = 0;
		child.timestamp = 0;
		child.count = 0;

		fprintf(out_dep_fp, "type=UBSI_CLONE msg=ubsi(%d.%d:%ld): dep=", child.thread_time.seconds, child.thread_time.milliseconds, eid);
		print_unit(&child, out_dep_fp);
		fprintf(out_dep_fp, ", unit=");
		print_unit(&uid, out_dep_fp);
		fprintf(out_dep_fp, "\n");

}

void exec_handler(int sysno, char *buf, FILE *fp)
{
		char *ptr, buf2[1048576];
		string path;
		int tid, pid, unitid;
		long eid, inode;
		thread_unit_t uid;

		ptr = strstr(buf, " unit=(");
		if(ptr == NULL) {
				fprintf(stderr, "PTR NULL: %s\n", buf);
		}
		assert(ptr);
		
		scan_unit(ptr+6, &uid);

		extract_long(buf, ":", 1, &eid);
		extract_int(buf, " pid=", 5, &tid);

		pid = get_pid(tid);

		fprintf(out_fp, "UBSI_PATH: EXEC unit=");
		print_unit(&uid, out_fp);
		fprintf(out_fp,  " (sysno %d, eid %ld, tid %d (pid %d)): ", sysno, eid, tid, pid);
	
		ptr = strstr(buf, "type=PATH");
		int i = 0;
		while(ptr == NULL)
		{
				if(i++ > 3) break;
				fgets(buf2, 1048576, fp);
				ptr = strstr(buf2, "type=PATH");
		}
		if(ptr == NULL) {
				fprintf(out_fp, "inode 0, path: \n");
				return;
		} 
		ptr+=9;
		path = extract_string(ptr, "name=", 5);
		extract_long(ptr, " inode=", 7, &inode); 

		fprintf(out_fp, "inode %ld, path:%s\n", inode, path.c_str());
}

void pt_syscall_handler(char *buf, FILE *fp)
{
		char *ptr;
		int sysno;

		ptr = strstr(buf, " syscall=");
		assert(ptr);
		sysno = strtol(ptr+9, NULL, 10);
		
		if(is_file_create(sysno)) {
				file_create_handler(sysno, buf);
		}

		if(is_exec(sysno)) {
				exec_handler(sysno, buf, fp);
		}
		if(is_read(sysno)) {
				read_handler(sysno, buf);
		}

		if(is_write(sysno)) {
				write_handler(sysno, buf);
		}
		if(is_fork_or_clone(sysno)) {
				fork_handler(sysno, buf);
		}

		fprintf(out_fp, "%s", buf);
}

void pt_dep_handler(char *buf)
{
		fprintf(out_dep_fp, "%s", buf);
}

void scan_and_print(FILE *fp)
{
		char *ptr;
		long fend, fcur;
		char buf[1048576], buf2[1048576];
		long sys_eid, eid;

		fgets(buf, 1048576, fp);
		while(!feof(fp)) 
		{
				ptr = strstr(buf, ":");

				eid = strtol(ptr+1, NULL, 10);

				if(strncmp(buf, "type=SYSCALL",12) == 0) {
						pt_syscall_handler(buf, fp);
				}

				if(strncmp(buf, "type=UBSI_DEP",13) == 0) {
						pt_dep_handler(buf);
				}

				fgets(buf, 1048576, fp);
		}
}

/*void scan_and_print(FILE *fp)
{
		char buf[1048576];

		printf("(2/4) Process system calls.\n");

		int j=0;
		for(int i = 0; i < fp_table_size; i++)
		{
				if(j++ > 1000) {
						loadBar(fp_table_size - i, fp_table_size, 10, 50);
						j = 0;
						}
				fseek(fp, fp_table[i][0], SEEK_SET);
				fread(buf, fp_table[i][1], 1, fp);
				buf[fp_table[i][1]] = '\0';
				pt_syscall_handler(buf);
		}
}
*/

void print_error()
{
		printf("Usage: ./UBSI_print [-i log_file] [-o out_file]\n");
}

int main(int argc, char** argv)
{
		bool load_init_table = true;

		FILE *fp;

		int opt = 0;
		char *log_name = NULL;
		char *out_name = NULL;
		char out_dep_name[128];
		char *init_table_name = NULL;
		char *f_name = NULL;
		char *p_name = NULL;

		while ((opt = getopt(argc, argv, "i:o:t:h")) != -1) {
				switch(opt) {
						case 'i':
								log_name = optarg;
								printf("Log file name=%s\n", log_name);
								break;
						case 'o':
								out_name = optarg;
								printf("Out file name=%s\n", log_name);
								break;
						case 'h':
								print_error();
								break;
				}
		}

		if(log_name == NULL || out_name == NULL) {
				print_error();
				return 0;
		}

		if((fp = fopen(log_name, "r")) == NULL) {
				printf("Error: Cannot open the log file: %s\n", log_name);
				print_error();
				return 0;
		}
		fclose(fp);


		if((out_fp = fopen(out_name, "w")) == NULL) {
				printf("Error: Cannot open the out file: %s\n", out_name);
				print_error();
				return 0;
		}

		
		sprintf(out_dep_name,  "%s.dep", out_name);
		if((out_dep_fp = fopen(out_dep_name, "w")) == NULL) {
				printf("Error: Cannot open the out file: %s\n", out_dep_name);
				print_error();
				return 0;
		}


/*
		if(init_table_name == NULL) {
				init_table_name = (char*) malloc(sizeof(char)*1024);
				sprintf(init_table_name, "%s_init_table.dat", log_name);
				printf("Init table name=%s\n", init_table_name);
		}

		init_table();

		printf("Load init_table (%s)\n", init_table_name);
		if(load_init_tables(init_table_name) == 0) load_init_table = false;

		if(!load_init_table) {
				if(!init_scan(log_name)) {
						printf("Error: Init scan failed! log file %s\n", log_name);
						printf("Usage: ./UBSI_ft [-i log_file] [-t init_table] [-f file_inode] [-p process_pid]\n");
						return 0;
				}
				printf("Save init_table (%s)\n", init_table_name);
				save_init_tables(init_table_name);
		}
*/
		init_scan(log_name);
		fp = fopen(log_name, "r");

		scan_and_print(fp);

		fclose(fp);
		fclose(out_fp);
		fclose(out_dep_fp);

		return 1;
}

