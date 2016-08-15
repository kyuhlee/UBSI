#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "auditlog.h"
#include "target.h"
#include "tainted_track.h"

INT USR_BEGIN, USR_END;
void printTarget()
{
		map<INT, TargetProcess>::iterator iter;
		set<string>::iterator iter2;
		bool only;
		
		set<INT>::iterator uiter;
		map<string, set<INT> >::iterator uiter2;
		for(uiter = user_inode.begin(); uiter != user_inode.end(); uiter++)
		{
				string ustr = inode_to_name(*uiter, max_log_num);
				debug("user insert : %s(%ld), log num = %ld\n", ustr.c_str(),*uiter, max_log_num);
				set<INT> ts;
				ts.insert(0);
				uiter2 = fileRead.find(ustr);
				if(uiter2 == fileRead.end()) {
						fileRead.insert(pair<string, set<INT> >(ustr,ts));
				} else uiter2->second.insert(0);
				uiter2 = fileWrite.find(ustr);
				if( uiter2 == fileWrite.end()) fileWrite.insert(pair<string, set<INT> >(ustr,ts));
				else uiter2->second.insert(0);
		}

		for(iter = targetProcess.begin(); iter != targetProcess.end(); iter++)
		{
				if(iter->second.fileread.empty() && iter->second.filewrite.empty() && iter->second.socketread.empty() && iter->second.socketwrite.empty() && iter->second.numChild == 0) continue; //KYU ignore processes who does not have any effect.

				if(iter->second.command.empty() || iter->second.command.size() < 1) ;//continue;
				string procNode = graph_add_processNode(iter->first, iter->second.command);
				if(iter->second.parent > 0) {
						string parentNode = graph_add_processNode(iter->second.parent, targetProcess[iter->second.parent].command);
						debug("KYU: graph parent: %s, %ld, comm %s\n", parentNode.c_str(), iter->second.parent, targetProcess[iter->second.parent].command.c_str());
						graph_add_edge(parentNode, procNode);
				}
				debug("Target process : %ld (%s) - parent %ld\n", iter->first, iter->second.command.c_str(), iter->second.parent);
				for(iter2 = iter->second.fileread.begin(); iter2 != iter->second.fileread.end(); iter2++)
				{
						only = false;
#ifdef IGNORE_LIB_CONF
						only = isLibOrConf(*iter2, iter->first);
#endif
#ifdef IGNORE_READONLY_FILE
						if(!only) only = isReadOnly(*iter2, iter->first);
#endif
						if(only) { debug("Target \t\tfileRead filtered out : %s\n", iter2->c_str());
						} else {
								debug("Target \t\tfileRead : %s\n", iter2->c_str());
								string fileReadNode = graph_add_fileNode(*iter2);
								graph_add_edge(fileReadNode, procNode);
						}
				}
				for(iter2 = iter->second.filewrite.begin(); iter2 != iter->second.filewrite.end(); iter2++)
				{
						only = false;
#ifdef IGNORE_WRITEONLY_FILE
						only = isWriteOnly(*iter2, iter->first);
#endif
						if(only) { debug("Target \t\tfileWrite (only) : %s\n", iter2->c_str());
						} else {
								debug("Target \t\tfileWrite : %s\n", iter2->c_str());
								string fileWriteNode;
								fileWriteNode = graph_add_fileNode(*iter2);
								debug("fileWriteNode = %s\n", fileWriteNode.c_str());
								graph_add_edge(procNode, fileWriteNode);
						}
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

void insert_target_file(INT spid, INT pid, INT unitid, INT inode, INT fd, INT log_num, bool isSocket, bool isWrite, bool isRename)
{
		string fileName;
		bool flag = false;
		bool temp;

		bool isLink = false;

		debug("insert_target_file[log %ld, pid %ld]: isSocket %d, isWrite %d\n", log_num, pid, isSocket, isWrite);
		if(logentry.sysnum == SYS_link) isLink = true;
		if(!isSocket || isRename || isLink) {
				fileName = inode_to_name(inode, log_num);
		} else {
				fileName = fd_to_name(spid, fd, log_num, &temp);
				if(isWrite)
						debug("log %ld: (%ld, %ld) insert_target_file: filename %s (write)\n", log_num, pid, unitid, fileName.c_str());
				else
						debug("log %ld: (%ld, %ld) insert_target_file: filename %s (read)\n", log_num, pid, unitid, fileName.c_str());
				if(!is_tainted_proc_list(pid, unitid)) debug("proc (%ld,%ld) is not tainted\n", pid, unitid);
				else debug("proc (%ld,%ld) is tainted\n", pid, unitid);
		}
		bool isLocalSocket = false;
		// TODO : need to handle local socket properly!!
		if(isSocket)
		{
				//if(fileName.empty() || fileName.size() < 1) return;
				if(fileName.compare(0,9, "localhost") == 0) {
						//printf("LOCALHOST : %s\n", fileName.c_str());
						isLocalSocket = true;
				} 
				if(fileName.compare(0,9, "127.0.0.1") == 0) {
						//printf("LOCALHOST : %s\n", fileName.c_str());
						isLocalSocket = true;
				}
				if(fileName.compare(0,5, "file:") == 0) {
						debug("LOCALHOST : %s\n", fileName.c_str());
						isLocalSocket = true;
				}
		}
		if(fileName.empty() || fileName.size() < 1) return;

		if(is_tainted_proc(pid, unitid))
		{
				if(isSocket) {
						bool temp;
						if(isWrite) {
#ifndef IGNORE_LOCAL_SOCKET
								if(isLocalSocket) {
										map<string, set<INT> >::iterator liter;
										liter = localSocket.find(fileName);
										if(liter != localSocket.end()){
												set<INT>::iterator liter2;
												for(liter2 = liter->second.begin(); liter2 != liter->second.end(); liter2++)
												{
														if(*liter2 != spid) liter->second.erase(liter2);
												}

										}
										//if(liter != localSocket.end()) localSocket.erase(liter);
									//	debug("Local socket tainted: Target add(%ld,%ld) : proc -> socket : %ld - %s\n", pid, unitid, spid, fileName.c_str()); 
								}
								//targetProcess[spid].socketwrite.insert(fileName);
#endif
						} else {
								if(isLocalSocket) {
										map<string, set<INT> >::iterator liter;
										liter = localSocket.find(fileName);
										//printf("LocalSocket: %s\n", fileName.c_str());
										if(liter == localSocket.end()) {
												set<INT> s;
												s.insert(spid);
												localSocket.insert(pair<string, set<INT> >(fileName, s));
										} else {
												liter->second.insert(spid);
										}
										//		localSocket.insert(pair<string, INT> (fileName, spid));
										debug("[%ld,%ld] Local socket tainted : socket -> proc : %ld - %s [%ld]\n", pid, unitid, spid, fileName.c_str(), logentry.log_num);
								}
								targetProcess[spid].socketread.insert(fileName);
						}
				} else {
						if(isWrite) {
								if(fileName.find("/tmp/") == string::npos) {
										debug("[%ld,%ld] File tainted : proc -> file : %ld - %s(%ld)\n", pid, unitid,  spid,fileName.c_str(),inode);
										targetProcess[spid].filewrite.insert(fileName);
								}
						} else {
								if(fileName.find("/tmp/") == string::npos) {
										targetProcess[spid].fileread.insert(fileName);
										debug("[%ld,%ld] File tainted : file -> proc : %ld - %s(%ld)\n", pid, unitid, spid, fileName.c_str(), inode);
								}
						}
						flag = true;
						insert_tainted_inode2(inode, isWrite);
				}
		} else if(!isSocket && is_tainted_inode(inode, isWrite)) {
				if(isWrite) {
						//if(fileName.find("/tmp/") == string::npos) 
								debug("[%ld,%ld] Proc tainted : proc -> file(new target proc) : %ld - %s(%ld)\n", pid,unitid, spid, fileName.c_str(), inode);
				} else {
						//if(fileName.find("/tmp/") == string::npos) 
								debug("[%ld,%ld] Proc tainted : file -> proc(new target proc) : %ld - %s(%ld)\n", pid, unitid, spid, fileName.c_str(), inode);
				}
				map<INT, TargetProcess>::iterator iter;
				iter = targetProcess.find(spid);
				if(iter == targetProcess.end()) {
						TargetProcess tp;
						tp.parent = -1;
						if(isWrite) 
								tp.filewrite.insert(fileName);
						else tp.fileread.insert(fileName);
						tp.command.assign(logentry.exe);
						targetProcess.insert(pair<INT, TargetProcess>(spid, tp));
				} else {
						if(isWrite) iter->second.filewrite.insert(fileName);
						else iter->second.fileread.insert(fileName);
				}
#ifdef WITHOUT_UNIT
				if(!isRename) insert_tainted_proc(pid, unitid);
#else
				if(!isRename) {
						//if(fileName.find("/tmp/") == string::npos)  {
								debug("insert_tainted_proc(rename), pid %ld, unitid %ld, filename %s(%ld)\n", pid, unitid, fileName.c_str(), inode);	
								insert_tainted_proc_list(pid, unitid);
						//}
				}
#endif
				flag = true;
		} else if(isSocket && isLocalSocket && isWrite) {
				map<string, set<INT> >::iterator lliter;
				lliter = localSocket.find(fileName);
				if(lliter != localSocket.end())
				{
						set<INT>::iterator llliter;
						for(llliter = lliter->second.begin(); llliter != lliter->second.end(); llliter++)
						{
								if(spid != *llliter) 
								{
										//#ifdef WITHOUT_UNIT
										//insert_tainted_proc(pid, unitid);
										//#else
										//printf("insert_tainted_proc(localSocket), pid %ld, unitid %ld, filename %s(%ld) (spid %ld, from spid %ld)\n", pid, unitid, fileName.c_str(), inode, spid, *llliter);	
										//insert_tainted_proc_list(pid, unitid);
										insert_tainted_proc(pid, unitid);
										insert_target_process(spid, logentry.exe, logentry.comm);
										targetProcess[spid].socketwrite.insert(fileName);
										debug("[%ld,%ld] Local socket tainted : proc -> socket : %ld - %s [%ld]\n", pid, unitid, spid, fileName.c_str(), logentry.log_num);
										//#endif
								}
								//localSocket.erase(lliter);
						}
				}
		}
		if(flag)
		{
				map<string, set<INT> >::iterator iter;
				if(isWrite) {
						iter = fileWrite.find(fileName);
						if(iter == fileWrite.end())
						{
								set<INT> s;
								s.insert(spid);
								fileWrite.insert(pair<string, set<INT> >(fileName, s));
						} else {
								iter->second.insert(spid);
						}
				} else {
						iter = fileRead.find(fileName);

						if(iter == fileRead.end())
						{
								set<INT> s;
								s.insert(spid);
								fileRead.insert(pair<string, set<INT> >(fileName, s));
						} else {
								iter->second.insert(spid);
						}
				}
		}
}

bool isWrite(INT sysnum)
{
		if(sysnum == SYS_write) return true;
		if(sysnum == SYS_writev) return true;
		if(sysnum == SYS_pwrite) return true;
		if(sysnum == SYS_pwritev) return true;
		if(sysnum == SYS_sendto) return true;
		if(sysnum == SYS_sendmsg) return true;
		if(sysnum == SYS_link) return true;

		return false;
}

bool isRead(INT sysnum)
{
		if(sysnum == SYS_read && logentry.success) return true;
		if(sysnum == SYS_readv && logentry.success) return true;
		if(sysnum == SYS_pread && logentry.success) return true;
		if(sysnum == SYS_preadv && logentry.success) return true;
		if(sysnum == SYS_recvfrom && logentry.success) return true;
		if(sysnum == SYS_recvmsg && logentry.success) return true;
		if(sysnum == SYS_accept && logentry.success) return true;
		if(sysnum == SYS_connect && logentry.exit == -4) return true;
		if(sysnum == SYS_getpeername && logentry.success) return true;
		//if(sysnum == SYS_open && logentry.success) return true; // for pine file attachment

		return false;
}

INT log_end(void)
{
		fseek(log_fd, -10, SEEK_END);
}

INT find_back()
{	
		char c;

		c = (char)fgetc(log_fd);
		while(c != '\n')
		{
				if(ftell(log_fd) < 2) return 0;
				fseek(log_fd, -2, SEEK_CUR);
				//printf("c = %c(%ld), fp = %ld\n", c,c, ftell(log_fd));
				c = (char)fgetc(log_fd);
		}

		return ftell(log_fd);
}


INT find_before(INT from)
{
		fseek(log_fd, from-2, SEEK_SET);

		return find_back();
}


INT log_reverse(void)
{
		static INT kyu_t = 0;
		static INT next_loc = 0;
		INT cur_loc;
		char temp[256];
		char *ptr;
		INT log_number;
		static INT prev_log_number = -1;

		if(next_loc) fseek(log_fd, next_loc-2, SEEK_SET);

		cur_loc = find_back();
		if(cur_loc == 0) return 0;

// read log_number for cur_loc
		fgets(temp, 256, log_fd);
		ptr = strstr(temp, ":");
		sscanf(ptr, ":%ld", &log_number);

		INT temp_loc1 = cur_loc;
		INT temp_loc2;
		
		INT ret = 1;
		do {
				temp_loc2 = find_before(temp_loc1);
				fgets(temp, 256, log_fd);
				ptr = strstr(temp, ":");
				if(ptr == NULL) {
						fprintf(stderr, "ERROR: %s\n", temp);
						exit(0);
				}
				sscanf(ptr, ":%ld", &prev_log_number);
				//printf("log_number = %ld, prev_log_number %ld, temp_loc1 = %ld\n", log_number, prev_log_number, temp_loc1);
				if(log_number == prev_log_number) {
						temp_loc1 = temp_loc2;
						ret++;
				}
		} while (log_number == prev_log_number);
		
		cur_loc = temp_loc1;
		fseek(log_fd, cur_loc, SEEK_SET);

		next_loc = cur_loc; 
		return ret;
}

void reverse_log(void)
{
		char temp[512];

		log_end();
		while(1)
		{
				if(process_log(log_reverse()) == 0) break;
						
				/*if(logentry.log_num > USR_BEGIN || logentry.log_num <= USR_END) {
						log_clean();
						continue;
				}*/
#ifdef WITHOUT_UNIT
				if(logentry.type == SYSCALL && logentry.success == false && logentry.sysnum != SYS_connect) {
#else 
				if(logentry.type == SYSCALL && logentry.sysnum != SYS_kill && logentry.success == false && logentry.sysnum != SYS_connect) {
				//if(logentry.type == SYSCALL && logentry.sysnum != SYS_kill && logentry.success == false) {
#endif
						log_clean();
						continue;
				}
				INT spid = get_parent_thread_id(logentry.pid);
#ifdef WITHOUT_UNIT
				logentry.pid = spid;
				logentry.unitid = 0;
#endif
				
				bool isSocket;
				if(logentry.sysnum == SYS_kill)
				{
#ifndef WITHOUT_UNIT
						if(is_unit_begin_backward()) {
								debug("[%ld,%ld] Unit begin\n", logentry.pid, logentry.unitid);
						}
#endif
						//unit_detect_mem();
					//if(is_unit_end())		clean_temp_list(false);
				} else if(logentry.sysnum == SYS_open && logentry.exit > 2)  {
						//bool isWrite = find_temp_write_fd(logentry.exit);
						//find_tainted_open(false);
				} else if(isRead(logentry.sysnum) && logentry.arg[0] > 2) {
						if(logentry.sysnum == SYS_accept) {
								logentry.arg[0] = logentry.exit;
								//logentry.inode = 1;
								isSocket = true;
						} else if(logentry.sysnum == SYS_connect) {
								isSocket = true;
						} else if(logentry.sysnum == SYS_getpeername) {
								isSocket = true;
						} else if(logentry.sysnum == SYS_recvfrom) {
								debug("[%ld,%ld] recvfrom:\n", logentry.pid, logentry.unitid);
								isSocket = true;
						} else {
								logentry.inode = fd_to_inode(logentry.pid, logentry.arg[0], logentry.log_num, &isSocket);
								debug("[%ld,%ld] read file: inode %ld\n", logentry.pid, logentry.unitid, logentry.inode);
						}
						if(isSocket || logentry.inode > 0) 
								insert_target_file(spid, logentry.pid, logentry.unitid, logentry.inode, logentry.arg[0], logentry.log_num, isSocket, false, false);
				} else if(isWrite(logentry.sysnum) && logentry.success && logentry.arg[0] > 2) {
						if(logentry.sysnum == SYS_link) {
								isSocket=false;
								//printf("SYSLINK : num %ld inode = %ld\n", logentry.log_num, logentry.inode);
								insert_target_file(spid, logentry.pid, logentry.unitid, logentry.inode, logentry.arg[0], logentry.log_num, isSocket, false, false); 
								// TODO : need to handle link properly!!
						} else {
								logentry.inode = fd_to_inode(logentry.pid, logentry.arg[0], logentry.log_num, &isSocket);
								debug("[%ld,%ld] write file: inode %ld, isSocket %d\n", logentry.pid, logentry.unitid, logentry.inode, isSocket);
						}
						if(isSocket || logentry.inode > 0) 
								insert_target_file(spid, logentry.pid, logentry.unitid, logentry.inode, logentry.arg[0], logentry.log_num, isSocket, true, false);
				} else if(logentry.sysnum == SYS_rename) {
						insert_target_file(spid, logentry.pid, logentry.unitid, logentry.inode, logentry.arg[0], logentry.log_num, isSocket, true, true);
				} else if(logentry.sysnum == SYS_unlink) {
						remove_tainted_inode(logentry.inode);
				} else if(logentry.sysnum == SYS_execve) {
						if(is_tainted_proc(logentry.pid, 0))
						{
								//if(targetProcess[spid].command.empty()) 
								//targetProcess[spid].command.append(inode_to_name(logentry.inode, logentry.log_num));
								debug("Tainted process exec : pid %ld, targetProcess.command %s, logentry.comm %s\n", logentry.pid, targetProcess[spid].command.c_str(), logentry.comm.c_str());
								//targetProcess[spid].command.append(logentry.comm);
								targetProcess[spid].command.assign(logentry.comm);
						}
						for(INT npath = 0; npath < logentry.num_path; npath++) {
								debug("KYU DEBUG : [%ld] isTainted %ld, execve pid %ld, inode %ld\n", logentry.log_num, is_tainted_proc(logentry.pid, 0), spid, logentry.extra_inodes[npath]);
								insert_target_file(spid, logentry.pid, logentry.unitid, logentry.extra_inodes[npath], logentry.arg[0], logentry.log_num, false, false, false);
						}
						//logentry.inode = fd_to_inode(logentry.pid, logentry.arg[0], logentry.log_num, &isSocket);
				} else if(logentry.sysnum == SYS_fork || logentry.sysnum == SYS_clone || logentry.sysnum == SYS_vfork) {
						if(is_tainted_proc(logentry.exit, 0)) {
							 debug("log %ld [%ld,%ld] Proc tainted (fork, clone) : proc[%ld,%ld] -> proc\n", logentry.log_num, logentry.exit, 0, logentry.pid, logentry.unitid);
#ifdef WITHOUT_UNIT
								insert_tainted_proc(logentry.pid, logentry.unitid);
#else
							insert_tainted_proc_list(logentry.pid, logentry.unitid);
							//insert_tainted_proc_list(logentry.pid, 0);
#endif
								targetProcess[logentry.exit].parent = logentry.pid;
								targetProcess[logentry.pid].numChild++;
								if(targetProcess[logentry.exit].command.empty()) {
										if(logentry.exe[0] == '/')
												targetProcess[logentry.exit].command.assign(logentry.exe);
										else targetProcess[logentry.exit].command.assign(logentry.comm);
								}
								debug("KYU: parent set.. my pid %ld, parent pid %ld\n", logentry.exit, logentry.pid);
								insert_target_process(spid, logentry.exe, logentry.comm);
						} else {
							 debug("log %ld [%ld,%ld] Proc not tainted (fork, clone) : proc[%ld,%ld] -> proc\n", logentry.log_num, logentry.exit, 0, logentry.pid, logentry.unitid);
						}
				}
				log_clean();
		}
		fclose(log_fd);

		printTarget();
}

extern int KYU_ignore_src;
extern int KYU_test_unit;
int main(int argc, char** argv)
{
		if(argc < 3) {
#ifdef WITHOUT_UNIT
				printf("Usage : ./bs_audit <auditlog file> [pid=xxx] [inode=xxx]\n");
#else
				printf("Usage : ./bs_beep <auditlog file> [pid=xxx] [inode=xxx]\n");
#endif
				return 1;
		}
		
		debug("Backward search!\n");
		if(strncmp(argv[2], "pid", 3) == 0) insert_tainted_proc_list(atol(argv[2]+4), 0);
		else if(strncmp(argv[2], "inode", 5) == 0) insert_inode(atol(argv[2]+6));
		else {
#ifdef WITHOUT_UNIT
				printf("Usage : ./bs_audit <auditlog file> [pid=xxx] [inode=xxx]\n");
#else
				printf("Usage : ./bs_beep <auditlog file> [pid=xxx] [inode=xxx]\n");
#endif
				return 1;
		}
		
		if(argc > 3) KYU_test_unit = atoi(argv[3]);
		else KYU_test_unit = 0;
//		printf("KYU_test_unit = %d\n", KYU_test_unit);

		INT user_input;
		strcpy(auditlog_name, argv[1]);
#ifdef KYU_TEST
		init_scan_test(false);  
		kyu_print_mem_access();
		return 0;
#endif
		init_scan(false); // to construct file information (inode - filename), (fd - inode), (fd - socket name), (thread creation)
		print_dep_units();
		//insert_inode(atol(argv[1]));
//		USR_BEGIN = atol(argv[2]);
//		USR_END = 0;
		graph_init();
		open_log();
		reverse_log();
		graph_fini();
		print_dep_units();
}

