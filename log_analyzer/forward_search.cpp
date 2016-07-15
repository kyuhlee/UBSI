#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include "auditlog.h"
#include "target.h"
#include "tainted_track.h"

typedef struct {
	bool isSocket;
	string name;
	INT inode;
} FName;

extern map<INT, INT> threadInfo;
map<INT, map<INT, FName> > fileNameFS;  //<pid, <fd, FileName> > 
set<string> UserInputFS;
map<string, INT> UserInputFoundFS;

map<INT, INT> parentList;

set<string> kyu_file_write;
void kyu_write_file_name(string name, INT inode, INT fd, string comm, INT pid){
	char temp[1024];
	sprintf(temp, "%s_%s_%ld_%ld_%ld\0", name.c_str(), comm.c_str(), inode, fd, pid);
	string tmp(temp);

	if(kyu_file_write.find(tmp) == kyu_file_write.end())
	{
		kyu_file_write.insert(tmp);
		//printf("KYU_WRITE %ld : name = %s, inode = %ld, fd = %ld, comm = %s(%ld)\n", logentry.log_num, name.c_str(), inode, fd, comm.c_str(), pid);
	}
}
void printTarget()
{
	map<INT, TargetProcess>::iterator iter;
	set<string>::iterator iter2;
	bool only;

	for(iter = targetProcess.begin(); iter != targetProcess.end(); iter++)
	{
		if(iter->second.command.empty() || iter->second.command.size() < 1) {
			debug("Graph: targetProcess command empty %ld\n", iter->first);
			continue;
		}
		//if(iter->second.filewrite.empty()) continue;
		//if(iter->second.filewrite.empty() && iter->second.child == false) continue; // Need to consider... KYU
		string procNode = graph_add_processNode(iter->first, iter->second.command);
		debug("Graph: add process - %s\n", iter->second.command.c_str());
		if(iter->second.parent > 0) {
			string parentNode = graph_add_processNode(iter->second.parent, targetProcess[iter->second.parent].command);
			graph_add_edge(parentNode, procNode);
		}
		debug("Graph: Target process : %ld (%s) - parnt %ld\n", iter->first, iter->second.command.c_str(), iter->second.parent);
		for(iter2 = iter->second.fileread.begin(); iter2 != iter->second.fileread.end(); iter2++)
		{
			only = isReadOnly(*iter2, iter->first);
			if(only) debug("Target \t\tfileRead (only) : %s\n", iter2->c_str());
			else {
				debug("Graph: Target \t\tfileRead : %s\n", iter2->c_str());
				string fileReadNode = graph_add_fileNode(*iter2);
				graph_add_edge(fileReadNode, procNode);
			}
		}
		for(iter2 = iter->second.filewrite.begin(); iter2 != iter->second.filewrite.end(); iter2++)
		{
			only = isWriteOnly(*iter2, iter->first);
			//if(only) debug("Graph: Target \t\tfileWrite (only) : %s\n", iter2->c_str());
			//else {
			debug("Graph: Target \t\tfileWrite : %s\n", iter2->c_str());
			string fileWriteNode;
			fileWriteNode = graph_add_fileNode(*iter2);
			debug("Graph: fileWriteNode = %s\n", fileWriteNode.c_str());
			graph_add_edge(procNode, fileWriteNode);
			//}
		}
		for(iter2 = iter->second.socketread.begin(); iter2 != iter->second.socketread.end(); iter2++)
		{
			debug("Target \t\tsocketRead : %s\n", iter2->c_str());
			string socketNode = graph_add_socketNode(*iter2);
			graph_add_edge(socketNode, procNode);
		}

		for(iter2 = iter->second.socketwrite.begin(); iter2 != iter->second.socketwrite.end(); iter2++)
		{
			debug("Target \t\tsocketWrite : %s\n", iter2->c_str());
			string socketNode = graph_add_socketNode(*iter2);
			graph_add_edge(procNode, socketNode);
		}

	}
}


bool is_local_socket(string name)
{
	if(name.empty() || name.size() < 1) return false;
	if(name.compare(0,9, "localhost") == 0) {
		//printf("LOCALHOST : %s\n", name.c_str());
		return true;
	} 
	if(name.compare(0,9, "127.0.0.1") == 0) {
		//printf("LOCALHOST : %s\n", name.c_str());
		//return true;
	}
	return false;
}

void read_process(INT spid, INT pid, INT unitid, INT inode, string name, bool isSocket)
{
	//printf("read_process : inode = %ld , name = %s\n", inode, name.c_str());
	bool flag = false;

	bool isLink = false;
	if(name.empty() || name.size() < 1) return;
	if(logentry.sysnum == SYS_link) isLink = true;

	bool isLocalSocket = false;
	// TODO : need to handle local socket properly!!

	if(isSocket)
		isLocalSocket = is_local_socket(name);

	if(!isSocket && is_tainted_proc(pid, unitid))
	{
		debug("Target add(%ld,%ld) : file -> proc : %ld - %s(%ld)\n", pid, unitid, spid, name.c_str(), inode);
		targetProcess[spid].fileread.insert(name);
	}
	if(!is_tainted_proc(pid, unitid) && !isSocket && is_tainted_inode(inode, false)) {
		debug("Target add(%ld,%ld) : file -> proc(new target proc) : %ld - %s(%ld)\n", pid, unitid, spid, name.c_str(), inode);
		map<INT, TargetProcess>::iterator iter;
		iter = targetProcess.find(spid);
		if(iter == targetProcess.end()) {
			insert_target_process(spid, logentry.exe, logentry.comm);
			iter = targetProcess.find(spid);
			iter->second.fileread.insert(name);
			if(user_file_name.empty() && user_inode.find(inode) != user_inode.end())  user_file_name.assign(name);
		} else {
			iter->second.fileread.insert(name);
			//iter->second.command.append(logentry.exe);
		}
		flag = true;
#ifdef WITHOUT_UNIT
		insert_tainted_proc(pid, unitid);
#else
		debug("insert_tainted_proc, pid %ld, unitid %ld, exe %s\n", pid, unitid, logentry.exe.c_str());
		insert_tainted_proc_list(pid, unitid);
#endif

	} 

	if(flag)
	{
		map<string, set<INT> >::iterator iter;
		iter = fileRead.find(name);

		if(iter == fileRead.end())
		{
			set<INT> s;
			s.insert(spid);
			fileRead.insert(pair<string, set<INT> >(name, s));
		} else {
			iter->second.insert(spid);
		}
	}
}

void write_process(INT spid, INT pid, INT unitid, INT inode, string name, bool isSocket, bool isRename)
{
	bool flag = false;

	bool isLink = false;

	if(name.empty() || name.size() < 1) {
		debug("file write: name is empty: %s, inode %ld\n", name.c_str(), inode);
		return;
	}

	if(logentry.sysnum == SYS_link) isLink = true;

	if(!is_tainted_proc(pid, unitid)) {
		debug("file write, proc not tainted: name %s, inode %ld, pid %ld, unitid %ld\n", name.c_str(), inode, pid, unitid);
		return;
	}

	bool isLocalSocket = false;
	// TODO : need to handle local socket properly!!

	if(isSocket)
		isLocalSocket = is_local_socket(name);

	if(is_tainted_proc(pid, unitid))
	{
		if(isSocket) {
			bool temp;
			//if(isLocalSocket) {
			//map<string, set<INT> >::iterator liter;
			//liter = localSocket.find(fileNameFS);
			//if(liter != localSocket.end()) localSocket.erase(liter);
			//}
			debug("Target add(%ld,%ld) : proc -> socket : %ld - %s\n", pid, unitid, spid, name.c_str()); 
			targetProcess[spid].socketwrite.insert(name);
		} else {
			debug("Target add(%ld,%ld) : proc -> file : %ld - %s(%ld)\n", pid, unitid,  spid, name.c_str(),inode);
			targetProcess[spid].filewrite.insert(name);
			flag = true;
			insert_tainted_inode2(inode, true);
		}
	}	else if(!isSocket){
		//printf("Target add NOT (%ld,%ld) : proc -> file : %ld - %s(%ld)\n", pid, unitid,  spid, name.c_str(),inode);
	}

	if(flag)
	{
		map<string, set<INT> >::iterator iter;
		iter = fileWrite.find(name);
		if(iter == fileWrite.end())
		{
			set<INT> s;
			s.insert(spid);
			fileWrite.insert(pair<string, set<INT> >(name, s));
		} else {
			iter->second.insert(spid);
		}
	}
}


void checkUserInputFS(string name)
{
	// if name is in UserInputFS, insert it to UserInputFoundFS, and check it to user.
}

string fd_to_name(INT pid, INT fd, bool *isSocket, INT *inode)
{
	INT spid = get_parent_thread_id(pid);
	debug("fd2inode : pid %ld, fd %ld\n", pid, fd);
	map<INT, map<INT, FName> >::iterator iter;

	iter = fileNameFS.find(spid);
	if(iter == fileNameFS.end())
	{
		//printf("ERROR : Can not find fd %ld of pid %ld (num %ld)\n", fd, pid, num);
		*inode = -1;
		return string();
	} else {
		map<INT, FName>::iterator iter2;

		iter2 = iter->second.find(fd);
		if(iter2 == iter->second.end())
		{
			debug("ERROR : Can not find fd %ld of pid %ld\n", fd, pid);
			*inode = -1;
			return string();
		}

		*inode = iter2->second.inode;
		*isSocket = iter2->second.isSocket;
		return string(iter2->second.name);
	}
	*inode = -1;
	return string();
}

INT close_filename(INT pid, INT fd)
{
	INT spid = get_parent_thread_id(pid);

	map<INT, map<INT, FName> >::iterator iter;
	map<INT, FName>::iterator iter2;

	iter = fileNameFS.find(spid);
	if(iter == fileNameFS.end()) return 0;

	iter2 = iter->second.find(fd);
	if(iter2 == iter->second.end()) return 0;

	iter->second.erase(iter2);

	return 1;
}

INT insert_filename(INT pid, INT fd, string name, INT inode, bool isSocket)
{
	INT spid = get_parent_thread_id(pid);

	if(isSocket){
		//printf("insert_sockname : pid %ld, spid %ld, fd %ld :  %s(inode %ld)\n", pid, spid, fd, name.c_str(), inode);
		if(name.empty()) return 0;
	} else {
		checkUserInputFS(name);
		debug("insert_inode : pid %ld, spid %ld, fd %ld : %s(inode %ld)\n", pid, spid, fd, name.c_str(), inode);
	}

	map<INT, map<INT, FName> >::iterator iter;
	map<INT, FName>::iterator iter2;

	iter = fileNameFS.find(spid);
	if(iter == fileNameFS.end())
	{
		FName fn;
		fn.name.append(name);
		fn.inode = inode;
		fn.isSocket = isSocket;

		map<INT, FName> m;
		m.insert(pair<INT, FName>(fd, fn));

		fileNameFS.insert(pair<INT, map<INT, FName> > (spid, m));
	} else {
		iter2 = iter->second.find(fd);
		if(iter2 == iter->second.end())
		{	
			FName fn;
			fn.name.append(name);
			fn.inode = inode;
			fn.isSocket = isSocket;

			iter->second.insert(pair<INT,FName>(fd,fn));
		} else {
			iter2->second.name.clear();
			iter2->second.name.append(name);
			iter2->second.isSocket = isSocket;
			iter2->second.inode = inode;
		}
	}
}


bool isWrite(INT sysnum)
{
	if(sysnum == SYS_write && logentry.exit > 0) return true;
	if(sysnum == SYS_writev && logentry.exit > 0) return true;
	if(sysnum == SYS_pwrite && logentry.exit > 0) return true;
	if(sysnum == SYS_pwritev && logentry.exit > 0) return true;
	if(sysnum == SYS_sendto && logentry.exit > 0) return true;
	if(sysnum == SYS_sendmsg && logentry.exit > 0) return true;
	if(sysnum == SYS_link) return true;

	return false;
}

bool isRead(INT sysnum)
{
	if(sysnum == SYS_read && logentry.exit > 0) return true;
	if(sysnum == SYS_readv && logentry.exit > 0) return true;
	if(sysnum == SYS_pread && logentry.exit > 0) return true;
	if(sysnum == SYS_preadv && logentry.exit > 0) return true;
	if(sysnum == SYS_recvfrom && logentry.exit > 0) return true;
	if(sysnum == SYS_recvmsg && logentry.exit > 0) return true;
	if(sysnum == SYS_accept && logentry.success) return true;
	if(sysnum == SYS_accept4 && logentry.success) return true;
	if(sysnum == SYS_connect && logentry.exit == -4) return true;
	if(sysnum == SYS_open && logentry.success) return true;

	return false;
}

INT fs_process_log2()
{
	static INT prev_num = 0;
	INT num;
	char *t;
	char temp[60480];

	INT fp;

	while(!feof(log_fd)) {
		fp = ftell(log_fd);
		fgets(temp, 60480, log_fd);
		t = strstr(temp, (char*)":");
		if(t == NULL) {
			return 0;
		}

		sscanf(t+1, "%ld", &num);

		if(prev_num == 0) prev_num = num;
		if(num != prev_num) {
			prev_num = num;
			fseek(log_fd, fp, SEEK_SET);
			return 1;
		}
		fseek(log_fd, fp, SEEK_SET);
		process_single_log(false);
	}
	return 0;
}

INT forward_search()
{
	open_log();
	INT last_log_num = 0;
	while(1)
	{
		if(fs_process_log2() == 0) break;
		if(last_log_num > logentry.log_num) {
			//fprintf(stderr, "Log file need to be sorted.. last log num %ld, current log num %ld\n", last_log_num, logentry.log_num);
		}
		last_log_num = logentry.log_num;
		if(logentry.type == SYSCALL && logentry.sysnum != SYS_kill && logentry.success == false && logentry.sysnum != SYS_connect) {
			debug("[%ld, %ld] Unit begin, log_num %ld!\n", logentry.pid, logentry.unitid, logentry.log_num);
			log_clean();
			continue;
		}

		INT spid = get_parent_thread_id(logentry.pid);
		string name;
		bool isSocket;
#ifdef WITHOUT_UNIT
		logentry.pid = spid;
		logentry.unitid = 0;
#endif

		if(logentry.sysnum == SYS_kill && logentry.success == false) {
#ifndef WITHOUT_UNIT
			// Construct unit dependency graph
			//is_unit_end();
			is_unit_begin_forward();
			debug("Unit begin [%ld,%ld], log_num %ld\n", logentry.pid, logentry.unitid, logentry.log_num);
			//	unit_detect_mem(spid, logentry.pid, logentry.unitid);
			//	is_tainted_proc_list(logentry.pid, logentry.unitid);
#endif
		} else if(logentry.sysnum == SYS_open && logentry.exit > 2) {
			debug("[%ld, %ld] SYS_open: filename = %s, inode = %ld, fd = %ld\n", logentry.log_num, logentry.unitid, logentry.fileName[0].c_str(), logentry.inode, logentry.exit);
			//printf("filename = %s\n", logentry.fileName[0].c_str());
			insert_filename(logentry.pid, logentry.exit, logentry.fileName[0], logentry.inode, false);
		} else if((logentry.sysnum == SYS_connect || logentry.sysnum == SYS_accept || logentry.sysnum == SYS_accept4)){ // && logentry.exit > -1)
			if(logentry.sysnum == SYS_accept || logentry.sysnum == SYS_accept4) logentry.arg[0] = logentry.exit;
			insert_filename(logentry.pid, logentry.arg[0], logentry.saddr, -1, true);
			//printf("KYU: SYS_accept, %ld - %s\n", logentry.log_num, logentry.saddr.c_str());
		} else if(logentry.sysnum == SYS_close && logentry.arg[0] > 2 && logentry.success) {
			close_filename(logentry.pid, logentry.arg[0]);
		} else if(logentry.sysnum == SYS_clone) {
			if(logentry.arg[2] > 0) { // thread create
				INT spid = get_parent_thread_id(logentry.pid);
				threadInfo.insert(pair<INT,INT>(logentry.exit, spid));
				//printf("set_parent_thread_id : %ld -> %ld\n", logentry.exit,spid);
			} else { // process create. inherit file table.
				INT new_spid = get_parent_thread_id(logentry.exit);
				INT old_spid = get_parent_thread_id(logentry.pid);
				inherit_file_table(old_spid, new_spid);
			}
		} else if((logentry.sysnum == SYS_pipe || logentry.sysnum == SYS_pipe2) && logentry.exit == 0) {
			debug("[%ld] SYS_pipe: fd0 %ld, fd1 %ld\n", logentry.log_num, logentry.fd_pair[0], logentry.fd_pair[1]);
		}

		if(isRead(logentry.sysnum)) {
			if(logentry.sysnum == SYS_accept) {
				logentry.arg[0] = logentry.exit;
				isSocket = true;
			} 
			if(logentry.sysnum == SYS_open) {
				logentry.arg[0] = logentry.exit;
			}
			/*
				  else if(logentry.sysnum == SYS_connect) {
				 isSocket = true;
				 } else {
				 isSocket =false;
				 }*/
			logentry.arg[0] = find_dup_fd(spid, logentry.arg[0]);
			name = fd_to_name(logentry.pid, logentry.arg[0],  &isSocket, &logentry.inode);
			//printf("name %s\n", name.c_str());
			name = fd_to_name(logentry.pid, logentry.arg[0],  &isSocket, &logentry.inode);
			if((name.empty() || name.size() < 1) && logentry.inode == -1) {} else {
				//printf("FILE READ : pid %ld, unitid %ld, inode %ld, name %s\n", logentry.pid, logentry.unitid, logentry.inode, name.c_str());
			}
			//printf("isRead : inode %ld, name %s\n", logentry.inode, name.c_str());

			if(isSocket || logentry.inode > 0) 
				read_process(spid, logentry.pid, logentry.unitid, logentry.inode, name, isSocket);
		} else if(isWrite(logentry.sysnum)) {
			if(logentry.sysnum == SYS_link) {
				isSocket=false;
				//printf("SYSLINK : num %ld inode = %ld\n", logentry.log_num, logentry.inode);
				if(logentry.inode > 0) {
					kyu_write_file_name(logentry.fileName[1], logentry.inode, logentry.arg[0], logentry.comm, logentry.pid);
				}
				//insert_target_file(spid, logentry.pid, logentry.unitid, logentry.inode, logentry.arg[0], logentry.log_num, isSocket, false, false); 
				// TODO : need to handle link properly!!
			} else {
				logentry.arg[0] = find_dup_fd(spid, logentry.arg[0]);
				name  = fd_to_name(logentry.pid, logentry.arg[0], &isSocket, &logentry.inode);
				if(logentry.inode > 0) {
					kyu_write_file_name(name, logentry.inode, logentry.arg[0], logentry.comm, logentry.pid);
				}
				debug("[%ld] write: pid %ld, name %s(inode %ld), isSocket %ld\n", logentry.log_num, logentry.pid, name.c_str(), logentry.inode, isSocket);
				if((name.empty() || name.size() < 1) && logentry.inode == -1) {} else {
					debug("FILE WRITE : pid %ld, unitid %ld, inode %ld, name %s\n", logentry.pid, logentry.unitid, logentry.inode, name.c_str());
					//if(logentry.sysnum == SYS_rename) printf("FILE WRITE : rename\n");
				}
			}
			if(isSocket || logentry.inode > 0) 
				write_process(spid, logentry.pid, logentry.unitid, logentry.inode, name, isSocket , false);
		} else if(logentry.sysnum == SYS_rename) {
			write_process(spid, logentry.pid, logentry.unitid, logentry.inode, logentry.fileName[0], false , true);
		} else if(logentry.sysnum == SYS_unlink) {
			write_process(spid, logentry.pid, logentry.unitid, logentry.inode, logentry.fileName[0], false , false);
			remove_tainted_inode(logentry.inode);
		} else if(logentry.sysnum == SYS_unlinkat) {
			write_process(spid, logentry.pid, logentry.unitid, logentry.inode, logentry.fileName[0], false , false);
			//printf("unlinkat: fileName[0] = %s, fileName[1] = %s\n", logentry.fileName[0].c_str(), logentry.fileName[0].c_str());
			remove_tainted_inode(logentry.inode);
		} else if(logentry.sysnum == SYS_execve) {
			if(is_tainted_inode(logentry.inode, false)) {
				insert_tainted_proc(logentry.pid, logentry.unitid);
				insert_target_process(spid, logentry.exe, logentry.comm);
				targetProcess[spid].parent = parentList[logentry.pid];
				targetProcess[parentList[logentry.pid]].child = true;
				targetProcess[spid].fileread.insert(logentry.fileName[0]);
			}
			if(is_tainted_proc(logentry.pid, logentry.unitid))
			{
				targetProcess[spid].command.assign(logentry.fileName[0]);
			}
			//logentry.inode = fd_to_inode(logentry.pid, logentry.arg[0], logentry.log_num, &isSocket);
			//printf("KYU DEBUG : execve inode %ld\n", logentry.inode);
			//insert_target_file(spid, logentry.pid, logentry.unitid, logentry.inode, logentry.arg[0], logentry.log_num, isSocket, false, false);
		} else if(logentry.sysnum == SYS_fork || logentry.sysnum == SYS_clone || logentry.sysnum == SYS_vfork) {
			//printf("clone : pid %ld, unitid %ld, exit %ld\n", logentry.pid, logentry.unitid, logentry.exit);
			if(is_tainted_proc(logentry.exit, 0)) {
				//#ifdef WITHOUT_UNIT
				insert_tainted_proc(logentry.pid, logentry.unitid);
				//printf("insert tainted proc : %ld\n", logentry.pid);
				//#else
				//							insert_tainted_proc_list(logentry.pid, logentry.unitid);
				//#endif
				insert_target_process(spid, logentry.exe, logentry.comm);
				targetProcess[logentry.exit].parent = logentry.pid;
				targetProcess[logentry.pid].child = true;
			}
			if(is_tainted_proc(logentry.pid, logentry.unitid)) {
				insert_tainted_proc(logentry.exit, 0);
				//printf("insert tainted proc child : %ld\n", logentry.exit);
				//#else
				//							insert_tainted_proc_list(logentry.pid, logentry.unitid);
				//#endif
#ifdef WITHOUT_UNIT
				if(logentry.sysnum != SYS_clone || logentry.arg[2] == 0) insert_target_process(logentry.exit, logentry.exe, logentry.comm);
#else
				insert_target_process(logentry.exit, logentry.exe, logentry.comm);
#endif
				targetProcess[logentry.exit].parent = logentry.pid;
				parentList[logentry.exit] = spid;
				//targetProcess[logentry.pid].child = true;
			}
		} else if((logentry.sysnum == SYS_dup || logentry.sysnum == SYS_dup2 || logentry.sysnum == SYS_dup3)) {
		//} else if(logentry.success && (logentry.sysnum == SYS_dup || logentry.sysnum == SYS_dup2 || logentry.sysnum == SYS_dup3)) {
			int oldfd, newfd;
			if(logentry.sysnum == SYS_dup) {
				oldfd = logentry.arg[0];
				newfd = logentry.exit;
			} else {
				oldfd = logentry.arg[0];
				newfd = logentry.arg[1];
			}
			insert_dup(spid, oldfd, newfd);
			printf("DUP insert: sysnum %d, oldfd %d, newfd %d, pid %d\n", logentry.sysnum, oldfd, newfd, logentry.pid);
			name = fd_to_name(logentry.pid, 4,  &isSocket, &logentry.inode);
			printf("name %s\n", name.c_str());
		}

		log_clean();
	}
	fclose(log_fd);

	printTarget();
}

INT insert_proc(INT pid)
{
	for(INT i = 0; i < 1000; i++)
		insert_tainted_proc_list(pid,  i);
	targetProcess[pid].child=true;
	targetProcess[pid].command.assign("ksmd");
}


int main(int argc, char** argv)
{
	if(argc != 3) {
#ifdef WITHOUT_UNIT
		printf("Usage : ./fs_audit <auditlog file> [pid=xxx] [inode=xxx]\n");
#else
		printf("Usage : ./fs_beep <auditlog file> [pid=xxx] [inode=xxx]\n");
#endif
		return 1;
	}

	if(strncmp(argv[2], "pid", 3) == 0) insert_proc(atol(argv[2]+4));
	else if(strncmp(argv[2], "inode", 5) == 0) insert_inode(atol(argv[2]+6));
	else {
#ifdef WITHOUT_UNIT
		printf("Usage : ./fs_audit <auditlog file> [pid=xxx] [inode=xxx]\n");
#else
		printf("Usage : ./fs_beep <auditlog file> [pid=xxx] [inode=xxx]\n");
#endif
		return 1;
	}

	is_forward_search = true;

	strcpy(auditlog_name, argv[1]);
	init_scan(true); // to construct file information (inode - filename), (fd - inode), (fd - socket name), (thread creation)
	unit_id_reset();
	debug("=====init done====\n");
	graph_init();
	open_log();
	forward_search();
	//reverse_log();
	graph_fini();
	//print_dep_units();
}

void inherit_file_table(INT old_spid, INT new_spid)
{
	map<INT, map<INT, FName> >::iterator iter;
	iter = fileNameFS.find(old_spid);
	if(iter == fileNameFS.end()) return;
	fileNameFS[new_spid].insert(iter->second.begin(), iter->second.end());
	printf("Inherit file table: from %d, to %d\n", old_spid, new_spid);
}
