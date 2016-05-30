/* 
	* 1. Search the log file forward to identify (fd - filename) pair.
	*    Also find out thread information.
	* 2. Traverse each log entry in backward way.
	* 3. The user provides file_name which is stored into dep.filename.
	* 4. When the log is exec or write one of dep.filename, than add that pid into dep list.
	* 5. When the log is open file or socket from dep.pid process, we add filename into dep.filename.
	*    (We don't log file read system call, we assume all open is file read.)
	* 6. If the log is fork, and child is dep.pid, add parent into dep.pid
	*
	* 7. If the file is W(pidA) -> R(pidB) and pidB is in dep.pid we add pidA and file into graph.
	* 8. If the file is R->W in the same process which is in dep.pid, and file is never written by other process,
	*    default is we don't insert R into graph.
	*    (If you want that infomation, #define INCLUDE_FILE_READ 1)
	* 9. If there is socket read (connect or accept) in dep.pid process, we insert all into the graph.
	* 
	* Rule A.
	* if(pid == dep.pid) {
	*				insert command file into dep.filename;
	*    insert all file write into dep.filename;
	*    insert all file read into dep.filename;
	*		}
	*
	*		for read, write and exec
	*		  if(filename == dep.filename)
	*		  add pid into dep.pid;
	*		  from now on, apply Rule A for this process.
	*		for fork
	*				if(child == dep.pid)
	*						add parent into dep.pid and add graph edge
	*
	*		for all dep.pid
	*		  if process has file write which is read from other process in dep.pid,
	*		    add edge
	*
	*
	*		For unit.
	*		  basically handle single unit as a processor.
	*		  If (unit == dep.unit) and has unit dependence to other unit A, unit A should added in dep.unit.
	*		  (not implemented)
	*
	*		For clone.
	*				fd and socket should be shared (not implemented)
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "auditlog.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

set<INT> user_inode;
string user_file_name;
FILE *log_fd, *new_log_fd;
LogEntry logentry;
INT max_log_num = 0;
char auditlog_name[256];
char parse_sock[256];

void print_log_entry(FILE *fp)
{
		if(logentry.success == false) fprintf(fp, "FAIL : ");
		fprintf(fp, "type=%ld  , ", logentry.type);
		fprintf(fp, "time=%ld.%ld, ", logentry.sec, logentry.mili);
		fprintf(fp, "log_num=%ld, ", logentry.log_num);
		fprintf(fp, "pid=%ld, ", logentry.pid);
		fprintf(fp, "ppid=%ld, ", logentry.ppid);
		fprintf(fp, "uid=%ld, ", logentry.uid);
		fprintf(fp, "auid=%ld, ", logentry.auid);
		if(logentry.type == SYSCALL) {
				fprintf(fp, "syscall=%s, ", get_syscall_name(logentry.sysnum));
				for(INT i = 0; i < 4; i++)
						fprintf(fp, "arg[%ld]=%lx, ", i, logentry.arg[i]);
				fprintf(fp, "exit=%ld, ", logentry.exit);
		}
		if(!logentry.comm.empty()) fprintf(fp, "comm=%s(%ld), ", logentry.comm.c_str(), logentry.inode);
		if(!logentry.hostname.empty()) fprintf(fp, "hostname=%s, ", logentry.hostname.c_str());
		if(!logentry.ext.empty()) fprintf(fp, "ext=%s, ", logentry.ext.c_str());
		if(!logentry.cwd.empty()) fprintf(fp, "cwd=%s, ", logentry.cwd.c_str());
		if(!logentry.saddr.empty()) fprintf(fp, "saddr=%s, ", logentry.saddr.c_str());
		for(INT i=0; i < logentry.fileNameNum; i++) fprintf(fp, "name=%s, ", logentry.fileName[i].c_str());
		for(INT i=0; i < logentry.dirNameNum; i++) fprintf(fp, "dirname=%s, ", logentry.dirName[i].c_str());
		if(!logentry.exe.empty()) fprintf(fp, "exe=%s, ", logentry.exe.c_str());
		fprintf(fp, "\n");

}
const char *get_syscall_name(INT num)
{
		syscall_num n = (syscall_num)num;

		if(n == SYS_open) return "open";
		else if(n == SYS_write) return "write";
		else if(n == SYS_socket) return "socket";
		else if(n == SYS_clone) return "clone";
		else if(n == SYS_execve) return "execve";
		else if(n == SYS_fork) return "fork";
		else if(n == SYS_kill) return "kill";
		else if(n == SYS_connect) return "connect";
		else if(n == SYS_accept) return "accept";
		else if(n == SYS_recvfrom) return "recvfrom";
		else return "unknown";
}


INT extract_time(char *s)
{
		char *ptr;

		ptr = strchr(s, '(');
		if (ptr) {
				logentry.sec = strtoul(ptr+1, NULL, 10);
				logentry.time.clear();
				logentry.time.append(ctime(&logentry.sec));
				if(logentry.time[logentry.time.size()-1] == '\n') logentry.time[logentry.time.size()-1] = '\0';
				ptr = strchr(ptr, '.');
				logentry.mili = strtoul(ptr+1, NULL, 10);
				ptr = strchr(ptr, ':');
				logentry.log_num = strtoul(ptr+1, NULL, 10);
				if(logentry.log_num > max_log_num) max_log_num = logentry.log_num;
				return 1;
		}
		return 0;
}

INT extract_long(char *s, const char *needle, INT size, long *store)
{
		char *ptr;

		ptr = strstr(s, needle);

		//if(ptr && sscanf(ptr+size, "%ld", store) > 0) return 1;
		if(ptr)
		{
				*store = strtol(ptr+size, NULL, 10);
				return 1;
		}

		return 0;
}

INT extract_int(char *s, const char *needle, INT size, INT *store)
{
		char *ptr;

		ptr = strstr(s, needle);

		//if(ptr && sscanf(ptr+size, "%ld", store) > 0) return 1;
		if(ptr)
		{
				*store = strtol(ptr+size, NULL, 10);
				return 1;
		}

		return 0;
}

INT socknum = 0;
map<string, INT> NoSocketName;
string handle_empty_sock(char *s)
{
		char tmp[11];
		INT num;
		strncpy(tmp, s, 10);
		tmp[10] = '\0';
		string name(tmp);

		map<string, INT>::iterator iter;
		iter = NoSocketName.find(name);
		if(iter == NoSocketName.end())
		{
				NoSocketName.insert(pair<string, INT>(name, socknum));
				num = socknum;
				socknum++;
		} else {
				num = iter->second;
		}

		sprintf(tmp, "s_%ld\n", num);
		return string(tmp);
}

size_t hexstr_to_bytes(uint8_t *dest, size_t n, const char *src)
{
		const char *pos = src;
		size_t i;
		for (i = 0; i < n && (pos[0] != '\0' && pos[1] != '\0'); i++) {
				sscanf(pos, "%2hhx", &dest[i]);
				pos += 2 * sizeof(pos[0]);
		}
		return i;
}

char *sockaddr_to_str(const struct sockaddr *sa, char *s, size_t n)
{
	size_t len;

	switch (sa->sa_family) {
		case AF_INET:
			inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr), 
					  s, n);
			len = strlen(s);
			snprintf(s+len, n-len, ":%ld", 
					 ((struct sockaddr_in *)sa)->sin_port);
			break;

		case AF_INET6:
			inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr), 
					  s, n);
			len = strlen(s);
			snprintf(s+len, n-len, ":%ld", 
					 ((struct sockaddr_in6 *)sa)->sin6_port);
			break;

		default:
			strncpy(s, "Unknown AF", n);
			return NULL;
	}

	return s;
}

string extract_sockaddr(char *ss, const char *needle, INT size)
{
 char *s = strstr(ss, needle);
	s += size;

	char temp[256], addr[128];
	int family;

	sprintf(temp, "perl %s -s %s",parse_sock, s);
	FILE *pe = popen(temp, "r");
	fscanf(pe, "%d %s\n", &family, addr);
	pclose(pe);

	//printf("family %d, addr %s\n", family, addr);

 if(family > 2) return handle_empty_sock(s);
	return string(addr);
	//const char *s = "0A00EFF30000000000000000000000000000FFFF800A7D4700000000";
	//const char *s = "020000357F0001010000000000000000";

/*
	uint8_t bytes[128] = {0,};
	struct sockaddr *sa = NULL;
	char str[128] = {0,};
	size_t i, sz;
	
	sz = hexstr_to_bytes(bytes, sizeof(bytes)/sizeof(bytes[0]), s);

	sa = (struct sockaddr *)bytes;

	if(sockaddr_to_str(sa, str, sizeof(str)/sizeof(str[0])) == NULL) return handle_empty_sock(s);
	return string(str);
*/
}
/*
string extract_sockaddr(char *s, const char *needle, INT size)
{
		char *ptr;
		char *ret;
		char two[5];
		struct sockaddr saddr;
		struct sockaddr_in sa;
		char name[NI_MAXHOST], serv[NI_MAXSERV];
		char t[16];
		ptr = strstr(s, needle);


		memset(name,0,sizeof(name));
		sprintf(name, "s_%ld", socknum++);
//		return string(name);  // for random socket num
		//if(ptr && sscanf((char*)(ptr+size), "%ld", store) > 0) return 1;
		if(ptr)
		{
				ptr+=size;
				two[0] = '0';
				two[1] = 'x';
				two[4] = '\0';
				//debug("log %ld, %s\n", logentry.mili, ptr);
				for(INT i =0; i < 16; i++)
				{
						two[2] = ptr[0];
						two[3] = ptr[1];
						sscanf(two, "%x", &t[i]);
			//		debug("t[i] = %x\n", t[i]);
			//		debug("two = %c%c%c%c\n", two[0], two[1], two[2], two[3]);
			//		debug("two = %s\n", two);
						ptr+=2;
				}
				memcpy(&saddr, t, sizeof(saddr));
				if (getnameinfo(&saddr, sizeof(struct sockaddr), name, NI_MAXHOST, serv, 	NI_MAXSERV, NI_NUMERICHOST | 
										NI_NUMERICSERV) == 0 ) {
					 debug("name = %s, serv = %s\n", name, serv);
						sprintf(name, "%s:%s\0", name, serv);
				}
		}
		if(ptr && name[0] == 0) return handle_empty_sock(ptr);
		return string(name);
}
*/

static unsigned char x2c(unsigned char *buf)
{
	static const char AsciiArray[17] = "0123456789ABCDEF";
	char *ptr;
	unsigned char total=0;

	ptr = strchr((char*)AsciiArray, (char)toupper(buf[0]));
	if (ptr)
		total = (unsigned char)(((ptr-AsciiArray) & 0x0F)<<4);
	ptr = strchr((char*)AsciiArray, (char)toupper(buf[1]));
	if (ptr)
		total += (unsigned char)((ptr-AsciiArray) & 0x0F);

	return total;
}

string extract_exe(string str)
{
		unsigned char tmp[1024];
		unsigned char c;
		for(INT i=0; i<str.size(); i++)
		{
				//tmp[i] = 
				c = (unsigned char)str[i];
				tmp[i] = x2c(&c);
		}

		tmp[str.size()] = '\0';

		//printf("extract_exe = %s\n", tmp);
		return string((const char *)tmp);
}
string extract_string(char *s, const char *needle, INT size)
{
		char *ptr;
		char *ret;

		ptr = strstr(s, needle);
		

		//if(ptr && sscanf(ptr+size, "%ld", store) > 0) return 1;
		if(ptr)
		{
				ptr+=size;
				if(ptr[0] == '"') ptr++;
				INT i=0;
				while(ptr[i] != ' ' && ptr[i] != '\n' && ptr[i] != '\0')
				{
						i++;
				}
				if(ptr[i-1] == '"') i--;
				
			return string(ptr, i);
			//return 1;
		//		ret = (char*)malloc(sizeof(char)*(i+1));
		//		strncpy(ret, ptr, i);
		//		ret[i] = '\0';

		//		return ret;
		}

		//return NULL;
		return string();
}

INT extract_hex_long(char *s, const char *needle, INT size, INT *store)
{
		char *ptr;

		ptr = strstr(s, needle);

		//if(ptr && sscanf(ptr+size, "%ld", store) > 0) return 1;
		if(ptr)
		{
				*store = strtol(ptr+size, NULL, 16);
				return 1;
		}

		return 0;
}

entry_type extract_type(char *s)
{
		char *ptr;

		ptr = strchr(s, '=');

		entry_type type = UNDEFINED;
		//if(ptr == NULL) return type;
		if(!strncmp(ptr+1, "DAEMON_START",12))
				type = DAEMON_START;
		else if(!strncmp(ptr+1, "USER_AUTH",9))
				type = USER_AUTH;
		else if(!strncmp(ptr+1, "USER_ACCT",9))
				type = USER_ACCT;
		else if(!strncmp(ptr+1, "CRED_ACQ",8))
				type = CRED_ACQ;
		else if(!strncmp(ptr+1, "LOGIN",5))
				type = LOGIN;
		else if(!strncmp(ptr+1, "USER_END",8))
				type = USER_END;
		else if(!strncmp(ptr+1, "USER_LOGIN",10))
				type = USER_LOGIN;
		else if(!strncmp(ptr+1, "USER_START",10))
				type = USER_START;
		else if(!strncmp(ptr+1, "USER_ROLE_CHANGE",16))
				type = USER_ROLE_CHANGE;
		else if(!strncmp(ptr+1, "SYSCALL",7))
				type = SYSCALL;
		else if(!strncmp(ptr+1, "CRED_DISP",9))
				type = CRED_DISP;
		else if(!strncmp(ptr+1, "SOCKADDR",8))
				type = SOCKADDR;
		else if(!strncmp(ptr+1, "CWD",3))
				type = CWD;
		else if(!strncmp(ptr+1, "PATH",4))
				type = PATH;
		else if(!strncmp(ptr+1, "EXECVE",6))
				type = EXECVE;
		else if(!strncmp(ptr+1, "FD_PAIR", 7))
				type = FD_PAIR;
		else
				type=ETC;
		return type;
}

bool get_absolute_path(Path *path, string cur_dir)
{
		bool isDir = false;
	
		if(cur_dir[cur_dir.size()-1] != '/') cur_dir.push_back('/');
		string name = path->name;
		if(name[name.size()-1] == '/') {
				name.erase(name.size()-1, 1);
				isDir = true;
		}
		if(name[0] == '.' && name[1] == '/') {
				name.erase(0, 2);
		}

		if(name[0] != '/') {
				name = cur_dir+name;
		}
		path->name.assign(name);

		return isDir;
}

INT process_single_log(bool scan)
{
		char temp[60480];
		
		fgets(temp, 60480, log_fd);
		//char temp[512];
		char needle[64];

		entry_type type = extract_type(temp);
		//logentry.unitid = 0;
		if(type < INCLUDEDFROMTHIS) {
				logentry.type = type;
				extract_time(temp);
				extract_int(temp, " pid=", 5,  &(logentry.pid));
#ifdef WITHOUT_UNIT
				logentry.unitid = 0;
#else
				map<INT,INT>::iterator ui;
				ui = unitId.find(logentry.pid);
				if(ui != unitId.end()) {
						logentry.unitid = ui->second;
						//debug("UNIT(%ld) : %ld, unitid = %ld\n", logentry.log_num, logentry.pid, ui->second);
				} else {
						if(scan) logentry.unitid = 0;
						else logentry.unitid = unitMax[logentry.pid];
				}
#endif
				extract_int(temp, " ppid=", 6,  &(logentry.ppid));
				extract_int(temp, " uid=", 5,  &(logentry.uid));
				extract_int(temp, " auid=", 6,  &(logentry.auid));
				if(type == SYSCALL) {
						extract_int(temp, " syscall=", 9, &(logentry.sysnum));
						extract_hex_long(temp, " a0=", 4, &(logentry.arg[0]));
						extract_hex_long(temp, " a1=", 4, &(logentry.arg[1]));
						extract_hex_long(temp, " a2=", 4, &(logentry.arg[2]));
						extract_hex_long(temp, " a3=", 4, &(logentry.arg[3]));
						extract_int(temp, " exit=", 6,  &(logentry.exit));
						logentry.comm.append(extract_string(temp, " comm=", 6));
						logentry.exe.append(extract_string(temp, " exe=", 5));
						//logentry.exe = extract_exe(logentry.exe);
						string str = extract_string(temp, " success=",9);
						if(!str.compare("yes")) logentry.success = true;
						else {
								logentry.success = false;
						}
				} 
				if(type >= USER_AUTH && type <= USER_ROLE_CHANGE)
				{
						logentry.hostname.append(extract_string(temp, " hostname=",10)); 
				}
		} else if(type ==SOCKADDR) {
						logentry.saddr.clear();
						logentry.saddr.append(extract_sockaddr(temp, " saddr=", 7));
					 debug	("sockname(%ld) : %s\n", logentry.log_num, logentry.saddr.c_str());
						//extract_sockaddr(temp, " saddr=", 7);
		}
		  else if(type ==CWD)
						logentry.cwd.append(extract_string(temp, " cwd=", 5));
				else if(type == PATH && logentry.num_path < MAX_PATH) {
						Path path;
						string mode;
						if(extract_int(temp, " inode=", 7, &(path.inode)) == 0) return 0;
						//printf("inode = %ld\n", path.inode);
						path.name.append(extract_string(temp, " name=", 6));
						mode.append(extract_string(temp, " mode=",6));
						if(mode[0] == '0' && mode[1] == '4') return 0;		// This is directory
						//string str2 = extract_string(temp, " mode=", 6);
						//if(!str2.empty() && str2.find("040550") != string::npos) return 0;
						//if(is_dir(str)) return 0;
						//if(!logentry.cwd.empty() && logentry.cwd.compare(str) == 0) return 0;
						if(path.name.compare("(null)") == 0 ) return 0;
						if(path.name.find("scoreboard") != string::npos) {
								logentry.inode = -1;
								return 0;
						}
						if(path.name.compare("/dev/null") == 0 ) return 0;
						if(path.name.size() == 1 && path.name[0] == '.' ) return 0;

						if(scan) scan_path_process(path, logentry.log_num, logentry.cwd);
						else {
								if(logentry.fileNameNum < 2 && !get_absolute_path(&path, logentry.cwd)) {
										logentry.fileName[logentry.fileNameNum].clear();
										logentry.fileName[logentry.fileNameNum].append(path.name);
										logentry.fileNameNum++;
								}
						}
						if(logentry.num_path == 0) 
								logentry.inode = path.inode;
						logentry.extra_inodes[logentry.num_path++] = path.inode;

						/*for(INT i = 0; i < MAX_PATH; i++)
						{
								if(logentry.path[i].empty()) {
										logentry.path[i].append(str);
										logentry.path_size = i+1;
										break;
								}
						}*/
				} else if(type == FD_PAIR) {
						extract_int(temp, " fd0=", 5,  &(logentry.fd_pair[0]));
						extract_int(temp, " fd1=", 5,  &(logentry.fd_pair[1]));
						debug("PIPE: fd0 %ld, fd1 %ld\n", logentry.fd_pair[0], logentry.fd_pair[1]);
				}

		//fprintf(new_log_fd, "%s", temp);
		//fflush(new_log_fd);
}

INT process_log(INT num)
{
		if(num == 0) {
				fseek(log_fd, 0, SEEK_SET);
				process_single_log(false);
				return 0;
		}

		for(INT i = 0; i < num; i++)
		{
				process_single_log(false);
		}
		
		return 1;
}

void log_clean()
{
		logentry.hostname.clear();
		logentry.ext.clear();
		logentry.terminal.clear();
		logentry.comm.clear();
		logentry.exe.clear();
		logentry.cwd.clear();
		logentry.saddr.clear();
		for(INT i=0; i < 2; i++) {
				logentry.fileName[i].clear();
				logentry.dirName[i].clear();
		}
		logentry.fileNameNum =0;
		logentry.dirNameNum =0;
		logentry.num_path = 0;
		logentry.type = UNDEFINED;
		logentry.sec = 0;
		logentry.mili = 0;
		logentry.log_num = 0;
		logentry.res = 0;
		logentry.uid = -1;
		logentry.auid = -1;
		logentry.pid = -1;
		logentry.ppid = -1;
		logentry.sysnum = 0;
		logentry.exit = -1;
		logentry.isWrite = false;
		logentry.success = false;
		logentry.inode = -1;
		for(INT i=0; i < 4; i++) 
				logentry.arg[i] = 0;
}

void open_log()
{
		log_fd = fopen(auditlog_name, "r");
		if(log_fd == NULL) {
				fprintf(stderr, "File open error : %s\n", auditlog_name);
				exit(0);
		}

		char temp[256];

		int ret = readlink("/proc/self/exe", temp, 256);
		int i;
		for(i = ret-1; i > 0; i--)
		{
				if(temp[i] == '/') {
						temp[i+1] = '\0';
						break;
				}
		}

		temp[ret] = 0;
		sprintf(parse_sock, "%sparse_sock.pl", temp);
		//printf("parse_sock.pl: %s\n", parse_sock);
}

bool is_dir(string str)
{
		if(str.compare(str.size()-1, 1, "/") == 0) return true;
		return false;
}

//INT user_selected_inode(INT inode)
INT insert_inode(INT inode)
{
		debug("user Inode: %ld\n", inode);
		user_inode.insert(inode);
		insert_tainted_inode2(inode, true);
		insert_tainted_inode2(inode, false);
}


