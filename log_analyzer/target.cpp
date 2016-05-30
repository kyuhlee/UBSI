#include <stdio.h>
#include <string.h>
#include "auditlog.h"
#include "target.h"
#include "tainted_track.h"

map<INT, TargetProcess> targetProcess;
map<string, set<INT> > fileWrite;
map<string, set<INT> > fileRead;
map<string, set<INT> > localSocket;

bool isLibOrConf(string name, INT pid)
{
		if(user_file_name.compare(name) == 0) return false;
		if(name.find(".conf") == string::npos
				&& name.find(".so") == string::npos
				&&	name.find(".lock") == string::npos
				&&	name.find(".pb") == string::npos 
				&&	name.find(".desktop") == string::npos
				&&	name.find(".service") == string::npos
				&&	name.find(".cache") == string::npos
				&&	name.find(".mozilla") == string::npos
					)  return false;

		map<string, set<INT> >::iterator iter;
		iter = fileWrite.find(name);

		if(iter == fileWrite.end()) return true;

		if(iter->second.size() == 1 && (iter->second.find(pid) != iter->second.end())) return true;

		return false;
}
bool isReadOnly(string name, INT pid)
{
		if(user_file_name.compare(name) == 0) return false;

		map<string, set<INT> >::iterator iter;
		iter = fileWrite.find(name);

		if(iter == fileWrite.end()) return true;

		if(iter->second.size() == 1 && (iter->second.find(pid) != iter->second.end())) return true;

		return false;
}

bool isWriteOnly(string name, INT pid)
{
		map<string, set<INT> >::iterator iter;
		iter = fileRead.find(name);

		if(iter == fileRead.end()) return true;

		if(iter->second.size() == 1 && (iter->second.find(pid) != iter->second.end())) return true;

		return false;

}

void insert_target_process(INT spid, string exe, string comm)
{
		string command;
		if(exe[0] == '/') command = exe;
		else command = comm;
		debug("insert_target_process %ld %s, %s\n", spid, comm.c_str(), exe.c_str());
		map<INT, TargetProcess>::iterator iter;
		iter = targetProcess.find(spid);
		if(iter == targetProcess.end()) {
				TargetProcess tp;
				tp.parent = -1;
				tp.child = false;
				tp.command.assign(command);
				targetProcess.insert(pair<INT, TargetProcess>(spid, tp));
		} else {
				//if(iter->second.command.empty() || iter->second.command.size() < 2)
						iter->second.command.append(command);
		}
}

