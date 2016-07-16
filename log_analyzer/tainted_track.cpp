#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "auditlog.h"

//map<string, string> taintedSocket;
set<string> taintedProc;
set<INT> taintedInode;
set<INT> taintedReadInode;
set<INT> taintedWriteInode;

map<INT, INT> unitId; // Need to check, I'm not sure this is necessary

string get_proc_str(INT pid, INT unitid)
{
		char temp[256];
		sprintf(temp, "%ld_%ld\0", pid, unitid);
		return string(temp);
}

bool is_tainted_proc(INT pid, INT unitid)
{
		string str = get_proc_str(pid, unitid);			
		set<string>::iterator iter;

		iter = taintedProc.find(str);
		if(iter == taintedProc.end()) return false;
		
		return true;
}

set<INT> taintedUnitList;

bool is_tainted_proc_list(INT pid, INT unitid)
{
		INT units = get_dep_units(pid, unitid);
		if(units == -1) return false;

		set<INT>::iterator iter;
		iter = taintedUnitList.find(units);
		if(iter != taintedUnitList.end()) return false;

		//taintedUnitList.insert(units);

		set<INT>::iterator iter2;

		for(iter2 = unitMap[units].begin(); iter2 != unitMap[units].end(); iter2++)
		{
				INT tpid, tunitid;
				tpid = (*iter2) >> 32;
				tunitid = (*iter2 << 32) >> 32;
				if(is_tainted_proc(tpid, tunitid)) {
						//printf("insert tainted proc - from %ld-%ld, to %ld-%ld\n", tpid, tunitid, pid, unitid);
						insert_tainted_proc(pid, unitid);			
						return true;
				}
		}
		return false;
}

void insert_tainted_proc_list(INT pid, INT unitid)
{
		debug("Proc tainted [%ld,%ld] added in the list.\n", pid, unitid);
		insert_tainted_proc(pid, unitid);
		
		INT units = get_dep_units(pid, unitid);
		debug("tainted list units = %ld\n", units);
		if(units == -1) return;

		set<INT>::iterator iter;
		iter = taintedUnitList.find(units);
		if(iter != taintedUnitList.end()) return;
		
		debug("tainted list units = %ld\n", units);
		print_dep_units();
		taintedUnitList.insert(units);

		set<INT>::iterator iter2;

		for(iter2 = unitMap[units].begin(); iter2 != unitMap[units].end(); iter2++)
		{
				INT tpid, tunitid;
				tpid = (*iter2) >> 32;
				tunitid = (*iter2 << 32) >> 32;

				insert_tainted_proc(tpid, tunitid);
				debug("Proc tainted [%ld,%ld] added in the list2.\n", tpid, tunitid);
		}
}

INT insert_tainted_proc(INT pid, INT unitid)
{
		if(logentry.comm.find("sudo") != string::npos) return 0;
		debug("Target proc tainted : (%ld, %ld)\n", pid, unitid);
		string str = get_proc_str(pid, unitid);			
		set<string>::iterator iter;
		
		iter = taintedProc.find(str);
		if(iter == taintedProc.end())
				taintedProc.insert(str);

	 str = get_proc_str(pid, 0);			
		
		iter = taintedProc.find(str);
		if(iter == taintedProc.end())
				taintedProc.insert(str);

}

void remove_tainted_inode(INT inode)
{
		if(user_inode.find(inode) != user_inode.end()) return;
		debug("Target inode removed : %ld\n", inode);
		set<INT>::iterator iter;

		iter = taintedWriteInode.find(inode);
		if(iter != taintedWriteInode.end())
				taintedWriteInode.erase(iter);

		iter = taintedReadInode.find(inode);
		if(iter != taintedReadInode.end())
				taintedReadInode.erase(iter);

		iter = taintedInode.find(inode);
		if(iter != taintedInode.end()) {
				//taintedInode.insert(inode);
				taintedInode.erase(iter);
		}
}

INT insert_tainted_inode2(INT inode, bool isWrite)
{
		debug("Target inode tainted : %ld\n", inode);
		if(isWrite) {
				taintedWriteInode.insert(inode);
				debug("Target Write inode tainted : %ld\n", inode);
		} else {
				taintedReadInode.insert(inode);
				debug("Target Read inode tainted : %ld\n", inode);
		}
		taintedInode.insert(inode);
}

bool is_tainted_inode(INT inode, bool isWrite)
{
		if(!isWrite)  {
				if(taintedWriteInode.find(inode) == taintedWriteInode.end()) return false;
		} else {
				if(taintedReadInode.find(inode) == taintedReadInode.end()) return false;
				//if(taintedInode.find(inode) == taintedInode.end()) return false;
		}
		return true;
}

