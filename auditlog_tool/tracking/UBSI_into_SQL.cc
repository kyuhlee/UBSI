#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <string>
#include <stdlib.h>
#include <assert.h>
#include "process_dep.h"
#include "uthash.h"
#include "utils.h"

#define BUFFER_LENGTH   10000
#define FALSE 0
#define TRUE		1

using namespace std;

FILE *out_fp;
int count = 0;

void process_buffer(char *buf, char *table_name)
{
		string comm, exe, path, type;
		int sysno, unitid, uid, euid, pid, ppid, ret;
		double time;
		long eid, inode;
		thread_unit_t unit;
		char *ptr;

		extract_int(buf, "syscall=", 8, &sysno);

		if(is_read(sysno)) {
				type = "READ";
		} else if(is_write(sysno) || is_file_create(sysno)) {
				type = "WRITE";
		} else if(is_file_delete(sysno)) {
				type = "DELETE";
		} else if(is_file_rename(sysno)) {
				type = "RENAME";
		} else if(is_exec(sysno)) {
				type = "EXEC";
		} else {
				return;
		}

		comm = extract_string(buf, "comm=", 5);
		exe = extract_string(buf, "exe=", 4);
		extract_int(buf, "uid=", 4, &uid);
		extract_int(buf, "euid=", 5, &euid);
		extract_int(buf, "pid=", 4, &pid);
		extract_int(buf, "ppid=", 5, &ppid);
		extract_int(buf, "exit=", 5, &ret);
		
		ptr = strstr(buf, "msg=audit(");
		if(ptr == NULL ) {
				fprintf(stderr, "%s\n", buf);
				assert(ptr);
		}
		sscanf(ptr+10, "%lf:%ld", &time, &eid);
		

		ptr = strstr(buf, " unit=(");
		assert(ptr);
		scan_unit(ptr+6, &unit);
		unitid = get_unitid(&unit);

		ptr = strstr(buf, "UBSI_PATH:");
		if(ptr != NULL) {
				path = extract_string(ptr+5, "path:", 5);
				extract_long(buf, "inode ", 6, &inode);
				//printf("paht %s, inode %d\n", path.c_str(), inode);
		} else {
				inode = 0;
				path = "";
		}

		//printf("%d, sysno %d, %s, %s\n", unitid, sysno, comm.c_str(), exe.c_str());
		if(count == 0) {
				fprintf(out_fp, "INSERT INTO %s (eid, time, etype, sysno, sysret, unitid, usrid, euid, pid, ppid, comm, exe, inode, path) VALUES ", table_name);
		} else fprintf(out_fp, ",");

		fprintf(out_fp, "(%ld, %.3lf, \"%s\", %d, %d, %d, %d, %d, %d, %d, \"%s\", \"%s\", %ld, \"%s\")", 
				eid, time, type.c_str(), sysno, ret, unitid, uid, euid, pid, ppid, comm.c_str(), exe.c_str(), inode, path.c_str());
		if(++count >= 10000) {
				count = 0;
				fprintf(out_fp, ";\n");
		}
}

void print_error()
{
		printf("Usage: ./UBSI_print [-i log_file] [-o out_file] [-t SQL_table_name]\n");
}

int main(int argc, char** argv)
{
		FILE *fp;
		int fcur, fend;
		char buffer[BUFFER_LENGTH*2];

		int opt = 0;
		char *log_name = NULL;
		char *out_name = NULL;
		char *table_name = NULL;
		char unit_table_name[128];
		char dep_file_name[128];

		while ((opt = getopt(argc, argv, "i:o:t:h")) != -1) {
				switch(opt) {
						case 'i':
								log_name = optarg;
								printf("Log file name=%s\n", log_name);
								break;
						case 'o':
								out_name = optarg;
								printf("Out file name=%s\n", out_name);
								break;
						case 't':
								table_name = optarg;
								printf("Table name=%s\n", table_name);
								break;
						case 'h':
								print_error();
								break;
				}
		}

		if(log_name == NULL || out_name == NULL || table_name == NULL) {
				print_error();
				return 0;
		}

		if((fp = fopen(log_name, "r")) == NULL) {
				printf("Error: Cannot open the log file: %s\n", log_name);
				print_error();
				return 0;
		}

		if((out_fp = fopen(out_name, "w")) == NULL) {
				printf("Error: Cannot open the out file: %s\n", out_name);
				print_error();
				return 0;
		}

		sprintf(dep_file_name,  "%s.dep", log_name);
		if(scan_dep_file(dep_file_name) < 0) {
				printf("Error: cannot open dep file: %s\n", dep_file_name);
				print_error();
				return 0;
		}

		fseek(fp, 0L, SEEK_END);
		fend = ftell(fp);
		fseek(fp, 0L, SEEK_SET);
		fcur = ftell(fp);
		int  i =0;

		do{
				while (TRUE) {
						memset(&buffer, 0, BUFFER_LENGTH);
						if(fgets(& buffer[0], BUFFER_LENGTH, fp) == NULL) {
								fprintf(stderr, "Reached the end of file (%s).\n", log_name);
								break;
						}
						if(strncmp(buffer, "UBSI_PATH:", 10) == 0) {
								if(fgets(& buffer[strlen(buffer)-1], BUFFER_LENGTH, fp) == NULL) {
										fprintf(stderr, "ERROR! reached the end of file after UBSI_PATH: %s\n", buffer);
										assert(0);
								}
						}
						process_buffer(buffer, table_name);
						fcur = ftell(fp);

						if(i++ > 10000) {
								loadBar(fcur, fend, 10, 50);
								i = 0;
						}
				}
		} while (FALSE);

		fprintf(out_fp, ";");

		sprintf(unit_table_name, "%s_unit", table_name);
		print_unit_table(out_fp, unit_table_name);
}


