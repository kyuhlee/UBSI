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

map<INT, INT> threadInfo;
map<INT, map<INT, FName> > fileName;  //<pid, <fd, FileName> > 
set<string> UserInput;
map<string, INT> UserInputFound;

void printTarget()
{
		map<INT, TargetProcess>::iterator iter;
		set<string>::iterator iter2;
		bool only;
		
		for(iter = targetProcess.begin(); iter != targetProcess.end(); iter++)
		{
				if(iter->second.command.empty() || iter->second.command.size() < 1) continue;
				string procNode = graph_add_processNode(iter->first, iter->second.command);
				if(iter->second.parent > 0) {
						string parentNode = graph_add_processNode(iter->second.parent, targetProcess[iter->second.parent].command);
						graph_add_edge(parentNode, procNode);
				}
				printf("Target process : %ld (%s) - parnt %ld\n", iter->first, iter->second.command.c_str(), iter->second.parent);
				for(iter2 = iter->second.fileread.begin(); iter2 != iter->second.fileread.end(); iter2++)
				{
						only = isReadOnly(*iter2, iter->first);
						if(only) printf("Target \t\tfileRead (only) : %s\n", iter2->c_str());
						else {
								printf("Target \t\tfileRead : %s\n", iter2->c_str());
								string fileReadNode = graph_add_fileNode(*iter2);
								graph_add_edge(fileReadNode, procNode);
						}
				}
				for(iter2 = iter->second.filewrite.begin(); iter2 != iter->second.filewrite.end(); iter2++)
				{
						only = isWriteOnly(*iter2, iter->first);
//						if(only) printf("Target \t\tfileWrite (only) : %s\n", iter2->c_str());
//						else {
								printf("Target \t\tfileWrite : %s\n", iter2->c_str());
								string fileWriteNode;
								fileWriteNode = graph_add_fileNode(*iter2);
								printf("fileWriteNode = %s\n", fileWriteNode.c_str());
								graph_add_edge(procNode, fileWriteNode);
//						}
				}
				for(iter2 = iter->second.socketread.begin(); iter2 != iter->second.socketread.end(); iter2++)
				{
						printf("Target \t\tsocketRead : %s\n", iter2->c_str());
						string socketNode = graph_add_socketNode(*iter2);
						graph_add_edge(socketNode, procNode);
				}
				for(iter2 = iter->second.socketwrite.begin(); iter2 != iter->second.socketwrite.end(); iter2++)
				{
						printf("Target \t\tsocketWrite : %s\n", iter2->c_str());
						string socketNode = graph_add_socketNode(*iter2);
						graph_add_edge(procNode, socketNode);
				}
		}
}


bool is_local_socket(string name)
{
		if(name.empty() || name.size() < 1) return false;
		if(name.compare(0,9, "localhost") == 0) {
				printf("LOCALHOST : %s\n", name.c_str());
				return true;
		} 
		if(name.compare(0,9, "127.0.0.1") == 0) {
				printf("LOCALHOST : %s\n", name.c_str());
				return true;
		}
		return true;
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

		if(!is_tainted_proc(pid, unitid) && !isSocket && is_tainted_inode(inode, false)) {
				printf("Target add(%ld,%ld) : file -> proc(new target proc) : %ld - %s(%ld)\n", pid, unitid, spid, name.c_str(), inode);
				map<INT, TargetProcess>::iterator iter;
				iter = targetProcess.find(spid);
				if(iter == targetProcess.end()) {
						insert_target_process(spid, logentry.exe, logentry.comm);
						iter = targetProcess.find(spid);
						iter->second.fileread.insert(name);
				} else {
						iter->second.fileread.insert(name);
				}
				flag = true;
//#ifdef WITHOUT_UNIT
				insert_tainted_proc(pid, unitid);
//#else
				printf("insert_tainted_proc, pid %ld, unitid %ld, filename %s(%ld)\n", pid, unitid, name.c_str(), inode);	
				//insert_tainted_proc_list(pid, unitid);
//#endif

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

		if(name.empty() || name.size() < 1) return;

		if(logentry.sysnum == SYS_link) isLink = true;

		if(!is_tainted_proc(pid, unitid)) return;

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
						//liter = localSocket.find(fileName);
						//if(liter != localSocket.end()) localSocket.erase(liter);
						//}
						printf("Target add(%ld,%ld) : proc -> socket : %ld - %s\n", pid, unitid, spid, name.c_str()); 
						targetProcess[spid].socketwrite.insert(name);
				} else {
						printf("Target add(%ld,%ld) : proc -> file : %ld - %s(%ld)\n", pid, unitid,  spid, name.c_str(),inode);
						targetProcess[spid].filewrite.insert(name);
						flag = true;
						insert_tainted_inode2(inode, true);
				}
		}	else if(!isSocket){
						printf("Target add NOT (%ld,%ld) : proc -> file : %ld - %s(%ld)\n", pid, unitid,  spid, name.c_str(),inode);
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


INT scan_path_process(Path path, INT num, string cur_dir)
{

}

void checkUserInput(string name)
{
		// if name is in UserInput, insert it to UserInputFound, and check it to user.
}

INT get_parent_thread_id(INT pid)
{
		INT spid = pid;
		map<INT, INT>::iterator iter;
		iter = threadInfo.find(pid);
		if(iter != threadInfo.end()) spid = iter->second;
		//printf("get_parent_thread_id : %ld -> %ld\n", pid,spid);
		return spid;
}

string fd_to_name(INT pid, INT fd, bool *isSocket, INT *inode)
{
		INT spid = get_parent_thread_id(pid);
		//printf("fd2inode : pid %ld, spid %ld, fd %ld, num %ld\n", pid, spid, fd, num);
		map<INT, map<INT, FName> >::iterator iter;

		iter = fileName.find(spid);
		if(iter == fileName.end())
		{
				//printf("ERROR : Can not find fd %ld of pid %ld (num %ld)\n", fd, pid, num);
				*inode = -1;
				return string();
		} else {
				map<INT, FName>::iterator iter2;

				iter2 = iter->second.find(fd);
				if(iter2 == iter->second.end())
				{
						//printf("ERROR : Can not find fd %ld of pid %ld (num %ld)\n", fd, pid, num);
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

		iter = fileName.find(spid);
		if(iter == fileName.end()) return 0;

		iter2 = iter->second.find(fd);
		if(iter2 == iter->second.end()) return 0;

		iter->second.erase(iter2);

		return 1;
}

INT insert_filename(INT pid, INT fd, string name, INT inode, bool isSocket)
{
		INT spid = get_parent_thread_id(pid);
		
		if(isSocket){
				printf("insert_sockname : pid %ld, spid %ld, fd %ld :  %s(inode %ld)\n", pid, spid, fd, name.c_str(), inode);
				if(name.empty()) return 0;
		} else {
				checkUserInput(name);
				//printf("insert_inode : pid %ld, spid %ld, fd %ld : %s(inode %ld)\n", pid, spid, fd, name.c_str(), inode);
		}

		map<INT, map<INT, FName> >::iterator iter;
		map<INT, FName>::iterator iter2;

		iter = fileName.find(spid);
		if(iter == fileName.end())
		{
				FName fn;
				fn.name.append(name);
				fn.inode = inode;
				fn.isSocket = isSocket;

				map<INT, FName> m;
				m.insert(pair<INT, FName>(fd, fn));

				fileName.insert(pair<INT, map<INT, FName> > (spid, m));
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
		if(sysnum == SYS_connect && logentry.exit == -4) return true;
		if(sysnum == SYS_open && logentry.success) return true;

		return false;
}

INT fs_process_log()
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
		while(1)
		{
				if(fs_process_log() == 0) break;

				if(logentry.type == SYSCALL && logentry.sysnum != SYS_kill && logentry.success == false && logentry.sysnum != SYS_connect) {
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
						is_unit_end();
						is_unit_begin_forward();
						unit_detect_mem(spid, logentry.pid, logentry.unitid);
						is_tainted_proc_list(logentry.pid, logentry.unitid);
#endif
				} else if(logentry.sysnum == SYS_open && logentry.exit > 2) {
						insert_filename(logentry.pid, logentry.exit, logentry.fileName[0], logentry.inode, false);
				} else if((logentry.sysnum == SYS_connect || logentry.sysnum == SYS_accept)){ // && logentry.exit > -1){
						if(logentry.sysnum == SYS_accept) logentry.arg[0] = logentry.exit;
						insert_filename(logentry.pid, logentry.arg[0], logentry.saddr, -1, true);
				} else if(logentry.sysnum == SYS_close && logentry.arg[0] > 2 && logentry.success) {
						close_filename(logentry.pid, logentry.arg[0]);
				} else if(logentry.sysnum == SYS_clone) {
						if(logentry.arg[2] > 0) {
								INT spid = get_parent_thread_id(logentry.pid);
								threadInfo.insert(pair<INT,INT>(logentry.exit, spid));
								//printf("set_parent_thread_id : %ld -> %ld\n", logentry.exit,spid);
						}
				} 
				if(isRead(logentry.sysnum) && logentry.arg[0] > 2) {
						if(logentry.sysnum == SYS_accept) {
								logentry.arg[0] = logentry.exit;
								isSocket = true;
						} 
						if(logentry.sysnum == SYS_open) {
								logentry.arg[0] = logentry.exit;
						}
						/*
						} else if(logentry.sysnum == SYS_connect) {
								isSocket = true;
						} else {
								isSocket =false;
						}*/
						name = fd_to_name(logentry.pid, logentry.arg[0],  &isSocket, &logentry.inode);
						if((name.empty() || name.size() < 1) && logentry.inode == -1) {} else {
										printf("FILE READ : pid %ld, unitid %ld, inode %ld, name %s\n", logentry.pid, logentry.unitid, logentry.inode, name.c_str());
						}
						//printf("isRead : inode %ld, name %s\n", logentry.inode, name.c_str());

						if(isSocket || logentry.inode > 0) 
								read_process(spid, logentry.pid, logentry.unitid, logentry.inode, name, isSocket);
				} else if(isWrite(logentry.sysnum) && logentry.arg[0] > 2) {
						if(logentry.sysnum == SYS_link) {
								isSocket=false;
								printf("SYSLINK : num %ld inode = %ld\n", logentry.log_num, logentry.inode);
								//insert_target_file(spid, logentry.pid, logentry.unitid, logentry.inode, logentry.arg[0], logentry.log_num, isSocket, false, false); 
								// TODO : need to handle link properly!!
						} else {
								name  = fd_to_name(logentry.pid, logentry.arg[0], &isSocket, &logentry.inode);
								if((name.empty() || name.size() < 1) && logentry.inode == -1) {} else {
										printf("FILE WRITE : pid %ld, unitid %ld, inode %ld, name %s\n", logentry.pid, logentry.unitid, logentry.inode, name.c_str());
										if(logentry.sysnum == SYS_rename) printf("FILE WRITE : rename\n");
								}
						}
						if(isSocket || logentry.inode > 0) 
								write_process(spid, logentry.pid, logentry.unitid, logentry.inode, name, isSocket , false);
				} else if(logentry.sysnum == SYS_rename) {
							write_process(spid, logentry.pid, logentry.unitid, logentry.inode, name, false , true);
				} else if(logentry.sysnum == SYS_unlink) {
						remove_tainted_inode(logentry.inode);
				} else if(logentry.sysnum == SYS_execve) {
						if(is_tainted_proc(logentry.pid, 0))
						{
								//targetProcess[spid].command.append(inode_to_name(logentry.inode, logentry.log_num));
						}
						//logentry.inode = fd_to_inode(logentry.pid, logentry.arg[0], logentry.log_num, &isSocket);
						printf("KYU DEBUG : execve inode %ld\n", logentry.inode);
						//insert_target_file(spid, logentry.pid, logentry.unitid, logentry.inode, logentry.arg[0], logentry.log_num, isSocket, false, false);
				} else if(logentry.sysnum == SYS_fork || logentry.sysnum == SYS_clone || logentry.sysnum == SYS_vfork) {
						if(is_tainted_proc(logentry.exit, 0)) {
//#ifdef WITHOUT_UNIT
							insert_tainted_proc(logentry.pid, logentry.unitid);
//#else
//							insert_tainted_proc_list(logentry.pid, logentry.unitid);
//#endif
								targetProcess[logentry.exit].parent = logentry.pid;
								insert_target_process(spid, logentry.exe, logentry.comm);
						}
				}


				log_clean();
		}
		fclose(log_fd);

		printTarget();
}

INT main(INT argc, char** argv)
{
		user_selected_inode(atoi(argv[1]));
		graph_init();
		open_log();
		forward_search();
		//reverse_log();
		graph_fini();
		//print_dep_units();
}

