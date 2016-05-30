#include <stdio.h>
#include <string.h>
#include <sched.h>
#include "auditlog.h"

typedef struct {
		bool isSocket;
		string name;
		INT inode;
} FName;

typedef struct {
		string fileName;
		bool isDir;
} FileName;

map<INT, INT> threadInfo;
map<INT, map<INT, map<INT, FName> > > fileName;  //<pid, <fd, <log_num, FName> > >
map<INT, map<INT, FileName> > inodeMap;
set<string> UserInput;
map<string, INT> UserInputFound;

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

INT fd_to_inode(INT pid, INT fd, INT num, bool *isSocket)
{
		INT spid = get_parent_thread_id(pid);
		//printf("fd2inode : pid %ld, spid %ld, fd %ld, num %ld\n", pid, spid, fd, num);
		pid = spid;
		map<INT, map<INT, map<INT, FName> > >::iterator iter;

		iter = fileName.find(pid);
		if(iter == fileName.end())
		{
				debug("ERROR : Can not find fd %ld of pid %ld (num %ld)\n", fd, pid, num);
				return -1;
		} else {
				map<INT, map<INT, FName> >::iterator iter2;

				iter2 = iter->second.find(fd);
				if(iter2 == iter->second.end())
				{
						debug("ERROR : Can not find fd %ld of pid %ld (num %ld)\n", fd, pid, num);
						return -1;
				}

				map<INT, FName>::iterator iter3;
				map<INT, FName>::iterator titer = iter2->second.end();

				for(iter3 = iter2->second.begin(); iter3 != iter2->second.end(); iter3++)
				{
						if(num >= iter3->first) titer = iter3;
						if(num < iter3->first) break;
				}

				if(titer != iter2->second.end())
				{
						*isSocket = titer->second.isSocket;
						debug("fd2name : pid %ld, fd %ld, num %ld : return %s\n", pid, fd, num, titer->second.name.c_str());
						return titer->second.inode; 

				} else {
						debug("ERROR : Can not find fd %ld of pid %ld (num %ld)\n", fd, pid, num);
						return -1;
				}
		}
		debug("ERROR : Can not find fd %ld of pid %ld (num %ld)\n", fd, pid, num);
		return -1;
}

string fd_to_name(INT pid, INT fd, INT num, bool *isSocket)
{
		INT spid = get_parent_thread_id(pid);
		//printf("fd2name : pid %ld, spid %ld, fd %ld, num %ld\n", pid, spid, fd, num);
		pid = spid;
		map<INT, map<INT, map<INT, FName> > >::iterator iter;

		iter = fileName.find(pid);
		if(iter == fileName.end())
		{
				//printf("ERROR : Can not find fd %ld of pid %ld (num %ld)\n", fd, pid, num);
				return string("");
		} else {
				map<INT, map<INT, FName> >::iterator iter2;

				iter2 = iter->second.find(fd);
				if(iter2 == iter->second.end())
				{
						//printf("ERROR : Can not find fd %ld of pid %ld (num %ld)\n", fd, pid, num);
						return string("");
				}

				map<INT, FName>::iterator iter3;
				map<INT, FName>::iterator titer = iter2->second.end();

				for(iter3 = iter2->second.begin(); iter3 != iter2->second.end(); iter3++)
				{
						if(num >= iter3->first) titer = iter3;
						if(num < iter3->first) break;
				}

				if(titer != iter2->second.end())
				{
						*isSocket = titer->second.isSocket;
						//printf("fd2name : pid %ld, fd %ld, num %ld : return %s\n", pid, fd, num, titer->second.name.c_str());
						return string(titer->second.name);

				} else {
						//printf("ERROR : Can not find fd %ld of pid %ld (num %ld)\n", fd, pid, num);
						return string("");
				}
		}
		//printf("ERROR : Can not find fd %ld of pid %ld (num %ld)\n", fd, pid, num);
		return string("");
}

INT insert_filename(INT pid, INT fd, string name, INT num, INT inode, bool isSocket)
{
		INT spid = get_parent_thread_id(pid);
		
		if(isSocket){
				if(name.empty()) return 0;
				//printf("insert_sockname : pid %ld, spid %ld, fd %ld, num %ld : %s(inode %ld)\n", pid, spid, fd, num, name.c_str(), inode);
		} else {
				checkUserInput(name);
				//printf("insert_inode : pid %ld, spid %ld, fd %ld, num %ld :(inode %ld)\n", pid, spid, fd, num, inode);
		}

		pid = spid;

		map<INT, map<INT, map<INT, FName> > >::iterator iter;
		map<INT, map<INT, FName> >::iterator iter2;
		map<INT, FName>::iterator iter3;

		iter = fileName.find(pid);
		if(iter == fileName.end())
		{
				FName fn;
				fn.name.append(name);
				fn.inode = inode;
				fn.isSocket = isSocket;

				map<INT, FName> m1;
				m1.insert(pair<INT, FName>(num, fn));

				map<INT, map<INT, FName> > m2;
				m2.insert(pair<INT, map<INT, FName> > (fd, m1));

				fileName.insert(pair<INT, map<INT, map<INT, FName> > > (pid, m2));
		} else {
				 iter2 = iter->second.find(fd);
					if(iter2 == iter->second.end())
					{	
							FName fn;
							fn.name.append(name);
							fn.inode = inode;
							fn.isSocket = isSocket;

							map<INT, FName> m1;
							m1.insert(pair<INT, FName>(num, fn));

						 iter->second.insert(pair<INT, map<INT, FName> > (fd, m1));
					} else {
							FName fn;
							fn.name.append(name);
							fn.inode =inode;
							fn.isSocket = isSocket;
							
							iter2->second.insert(pair<INT, FName>(num, fn));
					}
		}
}

string inode_to_name(INT inode, INT num)
{
		map<INT, map<INT, FileName> >::iterator inodeIter;
		char temp[128];

		inodeIter = inodeMap.find(inode);
		if(inodeIter == inodeMap.end()) {
				sprintf(temp, "FILE_NAME_NOT_FOUND! (inode %ld, log_num %ld)\n", inode, num);
				return string("");
		}

		map<INT, FileName>::reverse_iterator fmapIter;

		for(fmapIter = inodeIter->second.rbegin(); fmapIter != inodeIter->second.rend(); fmapIter++)
		{
				if(num >= fmapIter->first) return fmapIter->second.fileName;
		}

		sprintf(temp, "FILE_NAME_NOT_FOUND! (inode %ld, log_num %ld)\n", inode, num);
		return string("");
}

INT scan_path_process(Path path, INT num, string cur_dir)
{
		bool isDir = false;
		map<INT, map<INT, FileName> >::iterator inodeIter;
		
		if(cur_dir[cur_dir.size()-1] != '/') cur_dir.push_back('/');
		string name = path.name;
		if(name[name.size()-1] == '/') {
				name.erase(name.size()-1, 1);
				isDir = true;
		}
		if(name[0] == '.' && name[1] == '/') {
				name.erase(0, 2);
		}

		if(name[0] != '/') name = cur_dir+name;

		//printf("scan_path : name = %s\n", name.c_str());
		inodeIter = inodeMap.find(path.inode);
		if(inodeIter == inodeMap.end())
		{
				FileName fname;
				map<INT, FileName> fmap;

				fname.fileName.append(name);
				fname.isDir = isDir;
				
				fmap.insert(pair<INT, FileName>(num, fname));
				inodeMap.insert(pair<INT, map<INT, FileName> >(path.inode, fmap));
		} else {
				map<INT, FileName>::reverse_iterator fmapIter;
				fmapIter = inodeIter->second.rbegin();
				if(name.size() != fmapIter->second.fileName.size() || fmapIter->second.fileName.compare(name) != 0) {
						FileName fname;
						fname.fileName.append(name);
						fname.isDir = isDir;
						//printf("HERE\n");
						map<INT, FileName>::iterator fnameIter = inodeIter->second.find(num);
						if(fnameIter == inodeIter->second.end())
						inodeIter->second.insert(pair<INT, FileName> (num, fname));
				}
		}
}

void print_inode_map()
{
		map<INT, map<INT, FileName> >::iterator inodeIter;
		map<INT, FileName>::iterator fmapIter;

		for(inodeIter = inodeMap.begin(); inodeIter != inodeMap.end(); inodeIter++)
		{
				//printf("inode %ld - ", inodeIter->first);
				for(fmapIter = inodeIter->second.begin(); fmapIter != inodeIter->second.end(); fmapIter++)
				{
						//printf("%s(%ld), ",fmapIter->second.fileName.c_str(), fmapIter->first);
				}
				//printf("\n");
		}
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
//				if(num == 33028) {
						//printf("AAAAAAAAAAAAAAA\n");
//				}
				if(prev_num == 0) prev_num = num;
				if(num != prev_num) {
						prev_num = num;
						fseek(log_fd, fp, SEEK_SET);
						return 1;
				}
				fseek(log_fd, fp, SEEK_SET);
				process_single_log(true);
		}
		return 0;
}

INT init_scan_test(bool is_forwared_search)
{
		open_log();
		while(1)
		{
				if(fs_process_log() == 0) break;

				/*if(logentry.type == SYSCALL && logentry.sysnum != SYS_kill && logentry.success == false) {
						log_clean();
						continue;
				}*/
				
				INT spid = get_parent_thread_id(logentry.pid);
				if(logentry.sysnum == SYS_kill && logentry.success == false) {
						is_unit_begin_forward();
						unit_detect_mem(spid, logentry.pid, logentry.unitid);
				}
				log_clean();
		}
}

INT init_scan(bool is_forward_search)
{
		open_log();
		while(1)
		{
				if(fs_process_log() == 0) break;

				/*if(logentry.type == SYSCALL && logentry.sysnum != SYS_kill && logentry.success == false) {
						log_clean();
						continue;
				}*/
				
				INT spid = get_parent_thread_id(logentry.pid);
				if(logentry.sysnum == SYS_kill && logentry.success == false) {
#ifndef WITHOUT_UNIT
						// Construct unit dependency graph
						is_unit_begin_forward();
						unit_detect_mem(spid, logentry.pid, logentry.unitid);
#endif
				} else if((logentry.sysnum == SYS_open && logentry.exit > 2) || (logentry.sysnum == SYS_execve && logentry.exit>0))
				{
						if(is_forward_search) continue;
						insert_filename(logentry.pid, logentry.exit, string(""), logentry.log_num, logentry.inode, false);
				} else if((logentry.sysnum == SYS_connect || logentry.sysnum == SYS_accept)){ // && logentry.exit > -1){
						if(is_forward_search) continue;
						if(logentry.sysnum == SYS_accept) logentry.arg[0] = logentry.exit;
						//printf("num %ld, open path = %s, path_size = %ld\n", logentry.log_num, logentry.path[logentry.path_size-1].c_str(), logentry.path_size);
						//printf("sockname : KYU(%ld) %s\n", logentry.log_num, logentry.saddr.c_str());
						insert_filename(logentry.pid, logentry.arg[0], logentry.saddr, logentry.log_num, -1, true);
				} else if(logentry.sysnum == SYS_close) {
						if(is_forward_search) continue;
						//fd_to_inode(logentry.pid, logentry.arg[0], logentry.log_num, &isSocket);
						insert_filename(logentry.pid, logentry.arg[0], string(""), logentry.log_num, -1, false);
				} else if(logentry.sysnum == SYS_clone) {
						debug("logentry.arg[2] = %lx, %ld, %ld\n", logentry.arg[2], CLONE_THREAD, CLONE_FILES);
						//printf("logentry.arg[2] = %ld\n", logentry.arg[2]&CLONE_THREAD);
						//if(logentry.arg[2] & CLONE_FILES || logentry.arg[2] & CLONE_THREAD) { 
						if(logentry.arg[2] > 0) {
								INT spid = get_parent_thread_id(logentry.pid);
								threadInfo.insert(pair<INT,INT>(logentry.exit, spid));
							 debug("set_parent_thread_id : %ld -> %ld\n", logentry.exit,spid);
						}
				}
				log_clean();
		}
		fclose(log_fd);

		print_inode_map();
}

