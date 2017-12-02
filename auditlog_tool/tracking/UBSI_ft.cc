#include <stdio.h>
#include <unistd.h>
#include "init_scan.h"
#include "utils.h"
#include "tables.h"
#include "graph.h"

void write_handler(int sysno, char *buf)
{
		int fd, tid, pid, unitid;
		long eid;
		string exe;
		process_table_t *pt;

		fd = get_fd(sysno, buf);
		extract_long(buf, ":", 1, &eid);
		extract_int(buf, " pid=", 5, &tid);
		extract_int(buf, " unitid=", 8, &unitid);
#ifdef WITHOUT_UNIT
		unitid = -1;
#endif
		pid = get_pid(tid);

		pt = get_process_table(pid);

		if(is_tainted_unit(pt, tid, unitid) == false) return;

		fd_el_t *fd_el;
		fd_el = get_fd(pt, fd, eid);

		if(fd_el == NULL || fd_el->num_path == 0) {
				debug("pid %d, eid %ld, fd %d does not exist\n", pid, eid, fd);
				return;
		}

		debugbt("Taint file: WRITE fd %d (sysno %d, eid %ld, tid %d, unitid %d) (# path %d): inode %ld, path:%s, pathtype: %s\n",
						fd, sysno, eid, tid, unitid, fd_el->num_path, fd_el->inode[fd_el->num_path-1], 
						get_absolute_path(fd_el, fd_el->num_path-1).c_str(), fd_el->pathtype[fd_el->num_path-1].c_str());
		if(fd_el->is_socket) { // it is socket
				int t_socket = taint_socket(fd_el->path[fd_el->num_path-1]);
				edge_proc_to_socket(tid, unitid, t_socket);
		} else {
				taint_inode(fd_el->inode[fd_el->num_path-1], eid, get_absolute_path(fd_el, fd_el->num_path-1));
				edge_proc_to_file(tid, unitid, fd_el->inode[fd_el->num_path-1], eid);
		}
}

void read_handler(int sysno, char *buf)
{
		int fd, tid, pid, unitid;
		long eid;
		string exe;
		process_table_t *pt;

		extract_int(buf, " pid=", 5, &tid);
		extract_int(buf, " unitid=", 8, &unitid);
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
				exe = extract_string(buf, " exe=", 5);
				debugbt("tid %d, pid %d(%s), eid %ld, fd %d does not exist\n", tid, pid, exe.c_str(), eid, fd);
				return;
	 }
	
		if(fd_el->is_socket == false && is_tainted_inode(fd_el->inode[fd_el->num_path-1], eid)) { // only check the last path..
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
}

void file_create_handler(int sysno, char *buf)
{

}

void fork_handler(int sysno, char *buf)
{
		long a1, eid;
		int ret, tid, unitid;
		string exe;
		extract_hex_long(buf, " a1=", 4, &a1);	
		//printf("fork handler a1 %ld: %s\n", a1, buf);
		if(a1 > 0) return;
		
		extract_long(buf, ":", 1, &eid);
		extract_int(buf, " pid=", 5, &tid); 
		extract_int(buf, " unitid=", 8, &unitid); 
		process_table_t *pt = get_process_table(get_pid(tid));

		if(is_tainted_unit(pt, tid, unitid)) {
				extract_int(buf, " exit=", 6, &ret); 
				taint_all_units_in_pid(ret, "");
				edge_proc_to_proc(tid, unitid, ret);
				debugbt("Taint Process: fork (sysno %d) pid %d, unitid %d, exit %d\n", sysno, tid, unitid, ret);
		}
}

void exec_handler(int sysno, char *buf)
{
		char *ptr;
		string exe;
		int fd, tid, pid, unitid;
		long eid, inode;

		process_table_t *pt;

		extract_long(buf, ":", 1, &eid);
		extract_int(buf, " pid=", 5, &tid);
		extract_int(buf, " unitid=", 8, &unitid);

#ifdef WITHOUT_UNIT
				unitid = -1;
#endif

		pid = get_pid(tid);

		pt = get_process_table(pid);

		ptr = strstr(buf, "type=PATH");
		assert(ptr);

		ptr+=9;
		extract_long(ptr, " inode=", 7, &inode); 

		if(is_tainted_inode(inode, eid)) {
				exe = extract_string(buf, " exe=", 5);
				taint_all_units_in_pid(pid, exe);
				edge_file_to_proc(tid, -1, inode, eid);
				debugbt("taint unit (tid %d(pid %d), unitid %d, exe %s): exec (sysno %d, eid %ld), inode %ld\n", 
										tid, pid, -1, exe.c_str(),
										sysno, eid, inode);
		}
}

void ft_syscall_handler(char *buf)
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
				exec_handler(sysno, buf);
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
}

void scan(FILE *fp)
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
				ft_syscall_handler(buf);
		}
}

void test_fnc()
{
		string cwd, path;
		cwd = string("/home/kyuhlee/");
		path = string("/file1");
		printf("test: cwd %s, path %s, absolute %s\n", cwd.c_str(), path.c_str(), get_absolute_path(cwd, path).c_str());

}

int main(int argc, char** argv)
{
		bool load_init_table = true;

		FILE *fp;

		int opt = 0;
		char *log_name = NULL;
		char *init_table_name = NULL;
		char *f_name = NULL;
		char *p_name = NULL;

		while ((opt = getopt(argc, argv, "i:f:p:t:h")) != -1) {
				switch(opt) {
						case 'i':
								log_name = optarg;
								printf("Log file name=%s\n", log_name);
								break;
						case 't':
								init_table_name = optarg;
								printf("Init table name=%s\n", init_table_name);
								break;
						case 'f':
								f_name = optarg;
								user_inode = atol(f_name);
								printf("User Tainted File Inode=%s(%ld)\n", f_name, user_inode);
								break;
						case 'p':
								p_name = optarg;
								user_pid = atoi(p_name);
								printf("User Tainted Process Id=%s(%d)\n", p_name, user_pid);
								break;
						case 'h':
								printf("Usage: ./UBSI_ft [-i log_file] [-t init_table] [-f file_inode] [-p process_pid]\n");
								return 0;
								break;
				}
		}
		
		if(log_name == NULL || (user_inode == 0 && user_pid == 0)) {
				printf("Usage: ./UBSI_ft [-i log_file] [-t init_table] [-f file_inode] [-p process_pid]\n");
				return 0;
		}

		if((fp = fopen(log_name, "r")) == NULL) {
				printf("Error: Cannot open the log file: %s\n", log_name);
				printf("Usage: ./UBSI_ft [-i log_file] [-t init_table] [-f file_inode] [-p process_pid]\n");
				return 0;
		}
		fclose(fp);
		
		if(init_table_name == NULL) {
				init_table_name = (char*) malloc(sizeof(char)*1024);
				sprintf(init_table_name, "%s_init_table.dat", log_name);
				printf("Init table name=%s\n", init_table_name);
		}

		//user_inode = 701395;
		//user_pid=49039;

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
	
		fp = fopen(log_name, "r");
		generate_fp_table(fp);
		print_fp_table();
		
		if(user_pid > 0) {
				printf("user taint tid = %d, pid = %d\n", user_pid, get_pid(user_pid));
				taint_all_units_in_pid(user_pid, "start_node");
		}

		if(user_inode > 0) {
				string path;
				long user_eid = check_inode_list(user_inode, &path);
				if(user_eid < 0) return 1;
				taint_inode(user_inode, user_eid+1, path);
		}
		scan(fp);

		fclose(fp);
	
#ifdef WITHOUT_UNIT
		fp = fopen("AUDIT_ft.graph", "w");
#else
		fp = fopen("UBSI_ft.graph", "w");
#endif
		emit_graph(fp);
		emit_graph_detail(fp);
		fclose(fp);
//		test_fnc();
		return 1;
}

