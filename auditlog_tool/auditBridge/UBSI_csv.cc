#include <stdio.h>
#include <string.h>
#include <string>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sstream>
#include <iomanip>

#include "UBSI_utils.h"
#include "UBSI_auditBridge.h"

#define DELIMITER "; "

using namespace std;


typedef struct sysent {
		unsigned nargs;
		int sys_num;
		const char *sys_name;
} struct_sysent;

const struct_sysent sysent[] = { 
#include "syscall_list.h"
};

string filename_open_tmp(char *buf, int *inode)
{
		char *ptr = buf, *ptr2;
		int fd;
		string nametype, filename, path, cwd;
		stringstream str;
		
		while( (ptr=strstr(ptr, "type=PATH")) != NULL) {
				ptr2 = strstr(ptr, "nametype=NORMAL");
				if(ptr2 == NULL) ptr2 = strstr(ptr, "nametype=CREATE");
				if(ptr2 != NULL)
				{
						path = extract_string(ptr, "name=");
						if(extract_int(ptr, " inode=", inode) == 0) *inode=0;
						break;
				}
				ptr++;
		}
		
		if(ptr2 == NULL) {
				fprintf(stderr, "!!Cannot find a proper path: %s\n", buf);
				return string();
		}
		
/*		if(path[0] != '/') {
				cwd = extract_string(buf, "cwd=");
				if(path[0] == '.' && path[1] == '/') path.erase(0,1);
				else path.insert(0, "/");

				path.insert(0, cwd);
		}
*/
		return string(path);
}

string compose_fd(char *buf, const char *type, const char *keyword1, const char *keyword2, const char *keyword3, const char* keyword4, int fd, const char* ip, const char *port)
{
		char *ptr = buf;
		char *ptr2;
		int inode;
		string filename, path, cwd;
		stringstream str;

		if(buf == NULL) { // return empty fd events.
				if(fd > 0) str << fd << DELIMITER; //fd[n].num;
				else str << DELIMITER;
				if(type) str << type << DELIMITER; //fd[n].type;
				else str << DELIMITER;
				str << DELIMITER; //fd[n].filename;
				str << DELIMITER; //fd[n].name;
				str << DELIMITER; //fd[n].inode;
				if(ip) str << ip << DELIMITER;
				else str << DELIMITER;
				if(port) str << port << DELIMITER;
				else str << DELIMITER;
				
				return string(str.str());
		}
		
		while( (ptr=strstr(ptr, "type=PATH")) != NULL) {
				ptr2 = strstr(ptr, keyword1);
				if(ptr2 == NULL && keyword2) ptr2 = strstr(ptr, keyword2);
				if(ptr2 == NULL && keyword3) ptr2 = strstr(ptr, keyword3);
				if(ptr2 == NULL && keyword4) ptr2 = strstr(ptr, keyword4);

				if(ptr2 != NULL)
				{
						path = extract_string(ptr, "name=");
						if(extract_int(ptr, " inode=", &inode) == 0) inode=0;
						break;
				}
				ptr++;
		}
		
		if(path.empty()) {
				fprintf(stderr, "!!Cannot find a proper path: %s\n", buf);
				return string();
		}

		//cwd = extract_string(buf, "cwd=");
		//if(!cwd.empty()) str << "proc.cwd=" << cwd.c_str() << DELIMITER;
		
		// filename excluding path
		if(path.find("/") != string::npos) {
				size_t found = path.find_last_of("/");
				if(found != string::npos) {
						filename = path.substr(found+1);
				}
		}
		
		if(fd > 0) str << fd << DELIMITER;
		else str << DELIMITER;
		if(type) str << type << DELIMITER; //fd[n].type;
		else str << DELIMITER;
		str << filename.c_str() << DELIMITER;
		str << path.c_str() << DELIMITER;
		if(inode > 0) str << inode << DELIMITER;
		else str << DELIMITER;
		if(ip) str << ip << DELIMITER;
		else str << DELIMITER;
		if(port) str << port << DELIMITER;
		else str << DELIMITER;

		return string(str.str());
}

string compose_proc(char *buf) 
{
		// parse type=EXECVE, it contains target path and arguments
		int narg;
		int inode;
		char *ptr;
		char arg_t[16];
		bool notFirst;
		string filename, arg, path, tmp, cwd;
		stringstream str;
		
		ptr = strstr(buf, "type=CMD");
		if(ptr != NULL) {
				cwd = extract_string(ptr, " cwd=");
		}

		ptr = strstr(buf, "type=EXECVE");
		if(ptr != NULL) {
				if(extract_int(ptr, " argc=", &narg) > 0) {

						filename = extract_string(ptr, " a0=");

						for(int i = 0; i < narg; i++) {
								sprintf(arg_t, " a%d=", i);
								tmp = extract_string(ptr, arg_t);
								if(tmp.size()) {
										if(notFirst) sprintf(arg_t, " ");
										sprintf(arg_t, "a[%d]=",i);
										arg.append(arg_t);
										arg.append(tmp.c_str());
										notFirst = true;
								}
						}

						// filename excluding path
						if(filename.find("/") != string::npos) {
								size_t found = filename.find_last_of("/");
								if(found != string::npos) {
										filename = filename.substr(found+1);
								}
						}

						// find path and inode
						ptr = buf;
						while( (ptr=strstr(ptr, "type=PATH")) != NULL) {
								path.clear();
								path = extract_string(ptr, " name=");
								string last = path.substr(path.size() - filename.size());
								if(last.compare(filename) == 0) {
										if(extract_int(ptr, " inode=", &inode) == 0) {
												fprintf(stderr, "!! fail to find inode: %s\n", ptr);
												inode = 0;
										}
										break;
								}
								ptr++;
						}
				}
		}

		str << cwd << DELIMITER;
		str << arg << DELIMITER;
		str << path.c_str() << DELIMITER;
		if(inode > 0) str << inode << DELIMITER;
		else str << DELIMITER;

		return string(str.str());
}

string CSV_common(unit_table_t *ut, char *buf, const char *type)
{
		//evt.num; evt.datetime; evt.type; evt.res; evt.args; thread.tid; thread.unitid; proc.pid; proc.ppid; proc.name; proc.exepath; user.uid; user.euid; user.gid;
		stringstream str;
		char *ptr;

		time_t t;
		unsigned int mil;
		long eid, tmp;
		int uid, euid, gid, sysno, res, narg;
		string time, arg;
		char arg_t[256];

		if(extract_time(buf, &t, &mil) == 0 || 
				 extract_long(buf, ":", &eid) == 0 ||
					extract_int(buf, " uid=", &uid) == 0 ||
					extract_int(buf, " euid=", &euid) == 0 ||
					extract_int(buf, " gid=", &gid) == 0 ||
					extract_int(buf, "syscall=", &sysno) == 0) {
					fprintf(stderr, "Fail to extract default items: %s\n", buf);
				 return string();
		}
		

		if(type == NULL) {
				if(sysno <= 311) {
						narg = sysent[sysno].nargs;
				} else {
						narg = 4;
				}

				if (narg > 4) narg = 4; // audit only records 4 args

				for(int i = 0; i < narg; i++) {
						sprintf(arg_t, " a%d=", i);
						if(extract_hex_long(buf, arg_t, &tmp) > 0) {
								sprintf(arg_t, " a[%d]=0x%lx",i, tmp);
								arg.append(arg_t);
						}
				}
				arg.append(DELIMITER);
		} else arg.append(DELIMITER);
		
		time = convert_time(t, mil);

		str.setf(ios::fixed);
		str << eid << DELIMITER;
		str << t << "." << mil << "(" << time.c_str() << ")" << DELIMITER;
		if(type == NULL) {
				if(sysno <= 311) str << sysent[sysno].sys_name << "(" << sysno << ")" << DELIMITER;
				else str << "UNKNOWN(" << sysno << ")" << DELIMITER;
		} else str << type << DELIMITER;
		if(extract_int(buf, " exit=", &res) > 0) {
				str << res << DELIMITER;
		} else str << 0 << DELIMITER;

		str << arg;
		str << ut->thread.tid << "_" << ut->thread.thread_time.seconds << "." << ut->thread.thread_time.milliseconds << DELIMITER; // thread id
		if(UBSIAnalysis) str << setprecision(3) << ut->cur_unit.timestamp << "_" << ut->cur_unit.loopid << "_" << ut->cur_unit.iteration << DELIMITER;
		else str << DELIMITER;
		str << ut->pid << DELIMITER; // main thread id
		str << ut->ppid << DELIMITER;
		str << ut->comm << DELIMITER;
		str << ut->exe << DELIMITER;
		str << uid << DELIMITER;
		str << euid << DELIMITER;
		str << gid << DELIMITER;

		return string(str.str());
}

void CSV_execve(unit_table_t *ut, char *buf)
{
		string common, proc, s_fd0, s_fd1, dep;

		common = CSV_common(ut, buf, NULL);
		s_fd0 = compose_fd(NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL);
		s_fd1 = compose_fd(NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL);
		proc = compose_proc(buf);

		dep.append(DELIMITER); dep.append(DELIMITER);
		printf("%s%s%s%s%s\n", common.c_str(), s_fd0.c_str(), s_fd1.c_str(), proc.c_str(), dep.c_str());
}

void CSV_file_open(unit_table_t *ut, char *buf)
{
		string common, proc, s_fd0, s_fd1, dep;
		int fd;

		extract_int(buf, " exit=", &fd);

		common = CSV_common(ut, buf, NULL);
		s_fd0 = compose_fd(buf, "file", "nametype=NORMAL", "nametype=CREATE", NULL, NULL, fd, NULL, NULL);
		s_fd1 = compose_fd(NULL, NULL , NULL, NULL, NULL, NULL, 0, NULL, NULL);
		proc = compose_proc(buf);

		dep.append(DELIMITER); dep.append(DELIMITER);
		printf("%s%s%s%s%s\n", common.c_str(), s_fd0.c_str(), s_fd1.c_str(), proc.c_str(), dep.c_str());
}

void CSV_access_by_fd(unit_table_t *ut, char *buf, int fd, char* name, int inode, const char *type)
{
		int res;
		string common, proc, s_fd0, s_fd1, dep;
		stringstream ss;
		string filename;

		common = CSV_common(ut, buf, NULL);
		string name_t = string(name);

		if(name_t.find("/") != string::npos) {
				size_t found = name_t.find_last_of("/");
				if(found != string::npos) {
						filename = name_t.substr(found+1);
				}
		} else {
				filename = name_t;
		}

		if(extract_int(buf, " exit=", &res) == 0) res = -1;
		ss << fd << DELIMITER;
		ss << type << DELIMITER;
		ss << filename.c_str() << DELIMITER;
		ss << name << DELIMITER;
		ss << inode << DELIMITER;
		ss << DELIMITER;
		ss << DELIMITER;

		s_fd0.append(ss.str());
		s_fd1 = compose_fd(NULL, NULL , NULL, NULL, NULL, NULL, 0, NULL, NULL);
		proc = compose_proc(buf);
		
		dep.append(DELIMITER); dep.append(DELIMITER);
		printf("%s%s%s%s%s\n", common.c_str(), s_fd0.c_str(), s_fd1.c_str(), proc.c_str(), dep.c_str());
}


void CSV_file_access_by_name(unit_table_t *ut, char *buf, int sysno) 
{
		string common, proc, s_fd0, s_fd1, dep;

		common = CSV_common(ut, buf, NULL);
		s_fd0 = compose_fd(buf, "file", "nametype=NORMAL", "nametype=UNKNOWN", "nametype=CREATE", "nametype=DELETE", 0, NULL, NULL);
		s_fd1 = compose_fd(NULL, NULL , NULL, NULL, NULL, NULL, 0, NULL, NULL);
		proc = compose_proc(buf);
		
		dep.append(DELIMITER); dep.append(DELIMITER);
		printf("%s%s%s%s%s\n", common.c_str(), s_fd0.c_str(), s_fd1.c_str(), proc.c_str(), dep.c_str());
}

void CSV_default(unit_table_t *ut, char *buf)
{
		string common, proc, s_fd0, s_fd1, dep;

		common = CSV_common(ut, buf, NULL);
		s_fd0= compose_fd(NULL, NULL , NULL, NULL, NULL, NULL, 0, NULL, NULL);
		s_fd1 = compose_fd(NULL, NULL , NULL, NULL, NULL, NULL, 0, NULL, NULL);
		proc = compose_proc(buf);
		
		dep.append(DELIMITER); dep.append(DELIMITER);
		printf("%s%s%s%s%s\n", common.c_str(), s_fd0.c_str(), s_fd1.c_str(), proc.c_str(), dep.c_str());
}

void CSV_socket(unit_table_t *ut, char *buf, const char *sockaddr, int fd)
{
		string common, proc, s_fd0, s_fd1, dep;
		char family[256], addr[256], port[256];

		get_sockaddr(sockaddr, family, addr, port);
		
		common = CSV_common(ut, buf, NULL);
		s_fd0= compose_fd(NULL, family , NULL, NULL, NULL, NULL, fd, addr, port);
		s_fd1 = compose_fd(NULL, NULL , NULL, NULL, NULL, NULL, 0, NULL, NULL);
		proc = compose_proc(buf);
		
		dep.append(DELIMITER); dep.append(DELIMITER);
		printf("%s%s%s%s%s\n", common.c_str(), s_fd0.c_str(), s_fd1.c_str(), proc.c_str(), dep.c_str());
}

void CSV_socket2(unit_table_t *ut, char *buf, const char *sockaddr, int fd, const char *remote)
{
		string common, proc, s_fd0, s_fd1, dep;
		char family[256], addr[256], port[256];
		char family2[256], addr2[256], port2[256];

		get_sockaddr(sockaddr, family, addr, port);
		get_sockaddr(remote, family2, addr2, port2);

		common = CSV_common(ut, buf, NULL);
		s_fd0= compose_fd(NULL, family , NULL, NULL, NULL, NULL, fd, addr, port);
		s_fd1= compose_fd(NULL, family2 , NULL, NULL, NULL, NULL, 0, addr2, port2);
		proc = compose_proc(buf);
		
		dep.append(DELIMITER); dep.append(DELIMITER);
		printf("%s%s%s%s%s\n", common.c_str(), s_fd0.c_str(), s_fd1.c_str(), proc.c_str(), dep.c_str());
}

void CSV_pipe(unit_table_t *ut, char *buf, int fd0, int fd1)
{
		string common, proc, s_fd0, s_fd1, dep;

		common = CSV_common(ut, buf, NULL);
		s_fd0 = compose_fd(NULL, "pipe", NULL, NULL, NULL, NULL, fd0, NULL, NULL);
		s_fd1 = compose_fd(NULL, "pipe", NULL, NULL, NULL, NULL, fd1, NULL, NULL);
		proc = compose_proc(buf);
		
		dep.append(DELIMITER); dep.append(DELIMITER);
		printf("%s%s%s%s%s\n", common.c_str(), s_fd0.c_str(), s_fd1.c_str(), proc.c_str(), dep.c_str());
}

void CSV_link(unit_table_t *ut, char *buf, int sysno, int fd0, int fd1)
{
		string common, proc, s_fd0, s_fd1, dep;

		common = CSV_common(ut, buf, NULL);
		s_fd0 = compose_fd(buf, "file", "nametype=", NULL, NULL, NULL, fd0, NULL, NULL);
		s_fd1 = compose_fd(buf, "file", "nametype=CREATE", NULL, NULL, NULL, fd1, NULL, NULL);
		proc = compose_proc(buf);
		
		dep.append(DELIMITER); dep.append(DELIMITER);
		printf("%s%s%s%s%s\n", common.c_str(), s_fd0.c_str(), s_fd1.c_str(), proc.c_str(), dep.c_str());
}

void CSV_unlink(unit_table_t *ut, char *buf)
{
		string common, proc, s_fd0, s_fd1, dep;

		common = CSV_common(ut, buf, NULL);
		s_fd0 = compose_fd(buf, "file", "nametype=DELETE", NULL, NULL, NULL, 0, NULL, NULL);
		s_fd1 = compose_fd(NULL, NULL , NULL, NULL, NULL, NULL, 0, NULL, NULL);
		proc = compose_proc(buf);
		
		dep.append(DELIMITER); dep.append(DELIMITER);
		printf("%s%s%s%s%s\n", common.c_str(), s_fd0.c_str(), s_fd1.c_str(), proc.c_str(), dep.c_str());
}

void CSV_rename(unit_table_t *ut, char *buf, int sysno, int fd0, int fd1)
{
		string common, proc, s_fd0, s_fd1, dep;

		common = CSV_common(ut, buf, NULL);
		s_fd0 = compose_fd(buf, "file", "nametype=DELETE", NULL, NULL, NULL, fd0, NULL, NULL);
		s_fd1 = compose_fd(buf, "file", "nametype=CREATE", NULL, NULL, NULL, fd1, NULL, NULL);
		proc = compose_proc(buf);
		
		dep.append(DELIMITER); dep.append(DELIMITER);
		printf("%s%s%s%s%s\n", common.c_str(), s_fd0.c_str(), s_fd1.c_str(), proc.c_str(), dep.c_str());
}

void CSV_sendfile(unit_table_t *ut, char *buf, int in_fd, char *in_name, int in_inode, 
                 int out_fd, bool out_socket, char *out_name, int out_inode)
{
		string common, proc, s_fd0, s_fd1, dep;
		char family[256], addr[256], port[256];
		stringstream ss, ss2;
		string filename;

		common = CSV_common(ut, buf, NULL);
		proc = compose_proc(buf);	

		if(in_name) {
				string name_t = string(in_name);
				if(name_t.find("/") != string::npos) {
						size_t found = name_t.find_last_of("/");
						if(found != string::npos) {
								filename = name_t.substr(found+1);
						}
				} else {
						filename = name_t;
				}
				
				if(in_fd > 0) ss << in_fd << DELIMITER;
				else ss << DELIMITER;
				ss << "file" << DELIMITER;
				ss << filename.c_str() << DELIMITER;
				ss << in_name << DELIMITER;
				ss << in_inode << DELIMITER;
				ss << DELIMITER;
				ss << DELIMITER;
				s_fd0.append(ss.str());
		} else {
				s_fd0 = compose_fd(NULL, NULL, NULL, NULL, NULL, NULL, in_fd, NULL, NULL);
		}

		ss << "fd[1].num=" << out_fd << DELIMITER;
		if(out_name) {
				if(out_socket == false) {
						string name_t = string(out_name);
						if(name_t.find("/") != string::npos) {
								size_t found = name_t.find_last_of("/");
								if(found != string::npos) {
										filename = name_t.substr(found+1);
								}
						} else {
								filename = name_t;
						}

						if(out_fd > 0) ss2 << in_fd << DELIMITER;
						else ss2 << DELIMITER;
						ss2 << "file" << DELIMITER;
						ss2 << filename.c_str() << DELIMITER;
						ss2 << out_name << DELIMITER;
						ss2 << out_inode << DELIMITER;
						ss2 << DELIMITER;
						ss2 << DELIMITER;
						s_fd1.append(ss2.str());
				} else {
						// out_fd is socket
						get_sockaddr(out_name, family, addr, port);
						s_fd1 = compose_fd(NULL, family, NULL, NULL, NULL, NULL, out_fd, addr, port);
				}
		} else {
				s_fd1 = compose_fd(NULL, NULL, NULL, NULL, NULL, NULL, out_fd, NULL, NULL);
		}

		dep.append(DELIMITER); dep.append(DELIMITER);
		printf("%s%s%s%s%s\n", common.c_str(), s_fd0.c_str(), s_fd1.c_str(), proc.c_str(), dep.c_str());
}

void CSV_netio(unit_table_t *ut, char *buf, int fd, const char* fd_name, const char *local_addr, const char *remote_addr)
{
		string common, proc, s_fd0, s_fd1, dep;
		char family[256], addr[256], port[256];
		char family2[256], addr2[256], port2[256];

		family[0] = addr[0] = port[0] = 0;
		if(fd_name) {
						get_sockaddr(fd_name, family, addr, port);
		}
		if(remote_addr && (family[0] == 0 || addr[0] == 0)) {
						get_sockaddr(remote_addr, family, addr, port);
		}
	
		s_fd0= compose_fd(NULL, family , NULL, NULL, NULL, NULL, fd, addr, port);

		if(local_addr) {
				get_sockaddr(local_addr, family, addr, port);
				s_fd1= compose_fd(NULL, family , NULL, NULL, NULL, NULL, 0, addr, port);
		} else {
				s_fd1= compose_fd(NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL);
		}

		common = CSV_common(ut, buf, NULL);
		proc = compose_proc(buf);
		
		dep.append(DELIMITER); dep.append(DELIMITER);
		printf("%s%s%s%s%s\n", common.c_str(), s_fd0.c_str(), s_fd1.c_str(), proc.c_str(), dep.c_str());
}

void CSV_UBSI(unit_table_t *ut, char *buf, const char *evtType, const char *depTid, const char *depUnitid) 
{
		string common, proc, s_fd0, s_fd1, dep;
		stringstream str;
		char *ptr;

/*
		time_t t;
		unsigned int mil;
		long eid, tmp;
		int uid, euid, gid, sysno, res, narg;
		string time;
		char arg_t[256];

		if(extract_time(buf, &t, &mil) == 0 || 
				 extract_long(buf, ":", &eid) == 0 ||
					extract_int(buf, " uid=", &uid) == 0 ||
					extract_int(buf, " euid=", &euid) == 0 ||
					extract_int(buf, " gid=", &gid) == 0) {
					fprintf(stderr, "Fail to extract default items: %s\n", buf);
				 return;
		}
		
		time = convert_time(t, mil);
		str.setf(ios::fixed);
		str << eid << DELIMITER;
		str << t << "." << mil << "(" << time.c_str() << ")" << DELIMITER;
		str << evtType << DELIMITER;
		str << DELIMITER; // evt.res
		str << arg; // evt. 
		str << ut->thread.tid << "_" << ut->thread.thread_time.seconds << "." << ut->thread.thread_time.milliseconds << DELIMITER; // thread id
		str << setprecision(3) << ut->cur_unit.timestamp << "_" << ut->cur_unit.loopid << "_" << ut->cur_unit.iteration << DELIMITER;
		str << ut->pid << DELIMITER; // main thread id
		str << ut->ppid << DELIMITER;
		str << ut->comm << DELIMITER;
		str << ut->exe << DELIMITER;
		str << uid << DELIMITER;
		str << euid << DELIMITER;
		str << gid << DELIMITER;
		common.append(str.str());

*/

		common = CSV_common(ut, buf, evtType);
		s_fd0 = compose_fd(NULL, NULL , NULL, NULL, NULL, NULL, 0, NULL, NULL);
		s_fd1 = compose_fd(NULL, NULL , NULL, NULL, NULL, NULL, 0, NULL, NULL);
		proc = compose_proc(buf);

		if(depTid) str << depTid << DELIMITER;
		else str << DELIMITER;
		if(depUnitid) str << depUnitid << DELIMITER;
		else str << DELIMITER;
		dep.append(str.str());

		printf("%s%s%s%s%s\n", common.c_str(), s_fd0.c_str(), s_fd1.c_str(), proc.c_str(), dep.c_str());
}

