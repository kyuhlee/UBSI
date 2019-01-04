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

string find_filename(char *buf, const char *keyword1, const char *keyword2, const char *keyword3, const char* keyword4, int num)
{
		char *ptr = buf;
		char *ptr2;
		int inode, fd;

		string filename, path, cwd;
		stringstream str;
		
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

		cwd = extract_string(buf, "cwd=");
		
		// filename excluding path
		if(path.find("/") != string::npos) {
				size_t found = path.find_last_of("/");
				if(found != string::npos) {
						filename = path.substr(found+1);
				}
		}
		
		if(num < 0) {
				str << "fd.filename=" << filename.c_str() << DELIMITER;
				str << "fd.name=" << path.c_str() << DELIMITER;
				if(inode > 0) str << "fd.inode=" << inode << DELIMITER;
		} else {
				str << "fd[" << num << "].filename=" << filename.c_str() << DELIMITER;
				str << "fd[" << num << "].name=" << path.c_str() << DELIMITER;
				if(inode > 0) str << "fd[" << num << "].inode=" << inode << DELIMITER;
		}
		if(!cwd.empty()) str << "proc.cwd=" << cwd.c_str() << DELIMITER;

		return string(str.str());
}

string filename_execve(char *buf) 
{
		// parse type=EXECVE, it contains target path and arguments
		int narg;
		int inode;
		char *ptr;
		char arg_t[16];
		string filename, arg, path, tmp;
		stringstream str;
		
		ptr = strstr(buf, "type=EXECVE");
		if(ptr == NULL) {
				fprintf(stderr, "Fail to extract SYS_execve(path): [%s]\n", buf);
				return string();
		}
		
		if(extract_int(ptr, " argc=", &narg) == 0) {
				fprintf(stderr, "Fail to extract SYS_execve(argc): [%s]\n", buf);
				return string();
		}
		
		filename = extract_string(ptr, " a0=");
		if(filename.empty()) {
				fprintf(stderr, "Fail to extract SYS_execve(a0): [%s]\n", buf);
				return string();
		}

		for(int i = 1; i < narg; i++) {
				sprintf(arg_t, " a%d=", i);
				tmp = extract_string(ptr, arg_t);
				if(tmp.size()) {
						sprintf(arg_t, "proc.arg[%d]=",i);
						arg.append(arg_t);
						arg.append(tmp.c_str());
						arg.append(DELIMITER);
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
								printf("!! fail to find inode: %s\n", ptr);
								inode = 0;
						}
						break;
				}
				ptr++;
		}

		str << "proc.arg[0]=" << path.c_str() << DELIMITER;
		str << arg.c_str();
		if(inode > 0) 
				str << "proc.arg[0].inode=" << inode << DELIMITER;

		return string(str.str());
}

int* filename_pipe(char *buf) 
{
		// parse type=FD_PAIR. It has fd0=X fd1=Y (X,Y: int)
}

string CSV_common(unit_table_t *ut, char *buf)
{
		// evt.num; evt.datetime; evt.type; evt.res; evt.args; thread.tid; proc.pid; proc.ppid; proc.name; proc.exepath; user.uid; user.euid; user.gid; evt.type;

		stringstream str;
		char *ptr;

		time_t t;
		unsigned int mil;
		long eid, tmp;
		int uid, euid, gid, sysno, res, narg;
		string pname, time, arg;
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
		

		if(sysno <= 311) {
				narg = sysent[sysno].nargs;
		} else {
				narg = 4;
		}

		if (narg > 4) narg = 4; // audit only records 4 args

		for(int i = 0; i < narg; i++) {
				sprintf(arg_t, " a%d=", i);
				if(extract_hex_long(buf, arg_t, &tmp) > 0) {
						sprintf(arg_t, "evt.arg[%d]=0x%lx",i, tmp);
						arg.append(arg_t);
						arg.append(DELIMITER);
				}
		}

		time = convert_time(t, mil);

		str.setf(ios::fixed);
		str << "evt.num=" << eid << DELIMITER;
		str << "evt.datetime=" << t << "." << mil << "(" << time.c_str() << ")" << DELIMITER;
		if(sysno <= 311) str << "evt.type=" << sysent[sysno].sys_name << "(" << sysno << ")" << DELIMITER;
		else str << "evt.type=UNKNOWN(" << sysno << ")" << DELIMITER;
		if(extract_int(buf, " exit=", &res) > 0) {
				str << "evt.res=" << res << DELIMITER;
		}
		str << arg;
		str << "thread.tid=" << ut->thread.tid << "_" << ut->thread.thread_time.seconds << "." << ut->thread.thread_time.milliseconds << DELIMITER; // thread id
		if(UBSIAnalysis) str << "thread.unitid=" << setprecision(3) << ut->cur_unit.timestamp << "_" << ut->cur_unit.loopid << "_" << ut->cur_unit.iteration << DELIMITER;
		str << "proc.pid=" << ut->pid << DELIMITER; // main thread id
		str << "proc.ppid=" << ut->ppid << DELIMITER;
		str << "proc.name=" << ut->comm << DELIMITER;
		str << "proc.exepath=" << ut->exe << DELIMITER;
		str << "user.uid=" << uid << DELIMITER;
		str << "user.euid=" << euid << DELIMITER;
		str << "user.gid=" << gid << DELIMITER;

		return string(str.str());
}

void CSV_execve(unit_table_t *ut, char *buf)
{
		// evt.args
		string common, evt;

		common = CSV_common(ut, buf);
		evt = filename_execve(buf);

		printf("%s%s\n", common.c_str(), evt.c_str());
}

void CSV_file_open(unit_table_t *ut, char *buf)
{
		string common, evt, path;
		int fd;

		common = CSV_common(ut, buf);
		extract_int(buf, " exit=", &fd);

		path = find_filename(buf, "nametype=NORMAL", "nametype=CREATE", NULL, NULL, -1);

		printf("%sfd.num=%d%s%s\n", common.c_str(),fd, DELIMITER, path.c_str());
}

void CSV_access_by_fd(unit_table_t *ut, char *buf, int fd, char* name, int inode)
{
		int res;
		string common, evt;
		stringstream ss;
		string filename;
		common = CSV_common(ut, buf);
		
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
		ss << "fd.num=" << fd << DELIMITER;
		ss << "fd.filename=" << filename.c_str() << DELIMITER;
		ss << "fd.name=" << name << DELIMITER;
		ss << "fd.inode=" << inode << DELIMITER;
		evt.append(ss.str());
		
		printf("%s%s\n", common.c_str(), evt.c_str());
}


void CSV_file_access_by_name(unit_table_t *ut, char *buf, int sysno) 
{
		// parse type=PATH && nametype=DELETE
		string common, evt;

		common = CSV_common(ut, buf);
		//if(sysno == SYS_unlink || sysno == SYS_unlinkat) 
		evt = find_filename(buf, "nametype=NORMAL", "nametype=UNKNOWN", "nametype=CREATE", "nametype=DELETE", -1);

		printf("%s%s\n", common.c_str(), evt.c_str());
}

void CSV_default(unit_table_t *ut, char *buf)
{
		string common;

		common = CSV_common(ut, buf);
		printf("%s\n", common.c_str());
}

void CSV_socket(unit_table_t *ut, char *buf, const char *sockaddr, int fd)
{
		char family[256], addr[256], port[256];
		string common, evt;
		stringstream ss;

		common = CSV_common(ut, buf);
		get_sockaddr(sockaddr, family, addr, port);
		
		ss << "fd.num=" << fd << DELIMITER;
		if(family[0]) ss << "fd.sockfamily=" << family << DELIMITER;
		if(addr[0]) ss << "fd.ip=" << addr << DELIMITER;
		if(port[0]) ss << "fd.port=" << port << DELIMITER;
		evt.append(ss.str());

		printf("%s%s\n", common.c_str(), evt.c_str());
}

void CSV_socket2(unit_table_t *ut, char *buf, const char *sockaddr, int fd, const char *remote)
{
		char family[256], addr[256], port[256];
		string common, evt;
		stringstream ss;

		common = CSV_common(ut, buf);
		get_sockaddr(sockaddr, family, addr, port);
		
		ss << "fd.num=" << fd << DELIMITER;
		if(family[0]) ss << "fd.sockfamily=" << family << DELIMITER;
		if(addr[0]) ss << "fd.ip=" << addr << DELIMITER;
		if(port[0]) ss << "fd.port=" << port << DELIMITER;

		get_sockaddr(remote, family, addr, port);
		if(addr[0]) ss << "fd.local_ip=" << addr << DELIMITER;
		if(port[0]) ss << "fd.local_port=" << port << DELIMITER;

		evt.append(ss.str());

		printf("%s%s\n", common.c_str(), evt.c_str());
}

void CSV_pipe(unit_table_t *ut, char *buf, int fd0, int fd1)
{
		string common, evt;
		stringstream ss;

		common = CSV_common(ut, buf);

		ss << "fd[0].num=" << fd0 << DELIMITER;
		ss << "fd[1].num=" << fd1 << DELIMITER;
		evt.append(ss.str());

		printf("%s%s\n", common.c_str(), evt.c_str());
}

void CSV_link(unit_table_t *ut, char *buf, int sysno, int fd0, int fd1)
{
		// parse type=PATH && item=0 for oldname
		//       type=PATH && nametype=CREATE for newname

		string common, evt;
		stringstream ss;

		string oldname, newname;

		common = CSV_common(ut, buf);
		oldname = find_filename(buf, "nametype=", NULL, NULL, NULL, 0);
		newname = find_filename(buf, "nametype=CREATE", NULL, NULL, NULL, 1);

		if(fd0) ss << "fd[0].num=" << fd0 << DELIMITER;
		ss << oldname.c_str();
		if(fd1) ss << "fd[1].num=" << fd1 << DELIMITER;
		ss << newname.c_str();
		evt.append(ss.str());

		printf("%s%s\n", common.c_str(), evt.c_str());
}

void CSV_unlink(unit_table_t *ut, char *buf)
{
		// parse type=PATH && item=0 for oldname
		//       type=PATH && nametype=CREATE for newname

		string common, evt;
		stringstream ss;

		string oldname;

		common = CSV_common(ut, buf);
		oldname = find_filename(buf, "nametype=DELETE", NULL, NULL, NULL, 0);
		ss << oldname.c_str();
		evt.append(ss.str());

		printf("%s%s\n", common.c_str(), evt.c_str());
}

void CSV_rename(unit_table_t *ut, char *buf, int sysno, int fd0, int fd1)
{
		// parse type=PATH && nametype=DELETE for oldname 
		//       (if there are more then two items, choose the first one)
		//       type=PATH && nametype=CREATE for newname
		string common, evt;
		stringstream ss;

		string oldname, newname;

		common = CSV_common(ut, buf);
		oldname = find_filename(buf, "nametype=DELETE", NULL, NULL, NULL, 0);
		newname = find_filename(buf, "nametype=CREATE", NULL, NULL, NULL, 1);

		if(fd0) ss << "fd[0].num=" << fd0 << DELIMITER;
		ss << oldname.c_str();
		if(fd1) ss << "fd[1].num=" << fd1 << DELIMITER;
		ss << newname.c_str();
		evt.append(ss.str());

		printf("%s%s\n", common.c_str(), evt.c_str());
}

void CSV_sendfile(unit_table_t *ut, char *buf, int in_fd, char *in_name, int in_inode, 
                 int out_fd, bool out_socket, char *out_name, int out_inode)
{
		char family[256], addr[256], port[256];
		string common, evt, filename;
		stringstream ss;

		ss << "fd[0].num=" << in_fd << DELIMITER;
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

				ss << "fd[0].filename=" << filename.c_str() << DELIMITER;
				ss << "fd[0].name=" << in_name << DELIMITER;
				ss << "fd[0].inode=" << in_inode << DELIMITER;
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

						ss << "fd[1].filename=" << filename.c_str() << DELIMITER;
						ss << "fd[1].name=" << out_name << DELIMITER;
						ss << "fd[1].inode=" << out_inode << DELIMITER;
						evt.append(ss.str());
				} else {
						// out_fd is socket
						get_sockaddr(out_name, family, addr, port);
						if(family[0]) ss << "fd[1].sockfamily=" << family << DELIMITER;
						if(addr[0]) ss << "fd[1].ip=" << addr << DELIMITER;
						if(port[0]) ss << "fd[1].port=" << port << DELIMITER;
						evt.append(ss.str());
				}
		}

		common = CSV_common(ut, buf);
		evt.append(ss.str());

		printf("%s%s\n", common.c_str(), evt.c_str());
}

void CSV_netio(unit_table_t *ut, char *buf, int fd, const char* fd_name, const char *local_addr, const char *remote_addr)
{
		char family[256], addr[256], port[256];
		string common, evt, filename;
		stringstream ss;

		common = CSV_common(ut, buf);
		
		family[0] = addr[0] = port[0] = 0;
		if(fd_name) {
						get_sockaddr(fd_name, family, addr, port);
		}
		if(remote_addr && (family[0] == 0 || addr[0] == 0)) {
						get_sockaddr(remote_addr, family, addr, port);
		}
		
		ss << "fd.num=" << fd << DELIMITER;
		if(family[0]) ss << "fd.sockfamily=" << family << DELIMITER;
		if(addr[0]) ss << "fd.ip=" << addr << DELIMITER;
		if(port[0]) ss << "fd.port=" << port << DELIMITER;

		if(local_addr) {
				get_sockaddr(local_addr, family, addr, port);
				if(family[0]) ss << "fd.local_sockfamily=" << family << DELIMITER;
				if(addr[0]) ss << "fd.local_ip=" << addr << DELIMITER;
				if(port[0]) ss << "fd.local_port=" << port << DELIMITER;
		}

		evt.append(ss.str());

		printf("%s%s\n", common.c_str(), evt.c_str());
}

void CSV_UBSI(unit_table_t *ut, char *buf, const char *evtType, const char *depTid, const char *depUnitid) 
{
		// evt.num; evt.datetime; evt.type; thread.tid; proc.pid; proc.ppid; proc.name; proc.exepath; user.uid; user.euid; user.gid; 

		stringstream str;
		string common;
		char *ptr;

		time_t t;
		unsigned int mil;
		long eid, tmp;
		int uid, euid, gid, sysno, res, narg;
		string pname, time, arg;
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
		str << "evt.num=" << eid << DELIMITER;
		str << "evt.datetime=" << t << "." << mil << "(" << time.c_str() << ")" << DELIMITER;
		str << "evt.type=" << evtType << DELIMITER;
		str << "thread.tid=" << ut->thread.tid << "_" << ut->thread.thread_time.seconds << "." << ut->thread.thread_time.milliseconds << DELIMITER; // thread id
		str << "thread.unitid=" << setprecision(3) << ut->cur_unit.timestamp << "_" << ut->cur_unit.loopid << "_" << ut->cur_unit.iteration << DELIMITER;
		str << "proc.pid=" << ut->pid << DELIMITER; // main thread id
		str << "proc.ppid=" << ut->ppid << DELIMITER;
		str << "proc.name=" << ut->comm << DELIMITER;
		str << "proc.exepath=" << ut->exe << DELIMITER;
		str << "user.uid=" << uid << DELIMITER;
		str << "user.euid=" << euid << DELIMITER;
		str << "user.gid=" << gid << DELIMITER;
		if(depTid) str << "dep.tid=" << depTid << DELIMITER;
		if(depUnitid) str << "dep.unitid=" << depUnitid << DELIMITER;

		common.append(str.str());
		printf("%s\n", common.c_str());
}
