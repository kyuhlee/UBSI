#include <stdio.h>
#include "auditlog.h"

FILE *gfp;
bool is_forward_search = false;

typedef struct {
		string name;
		string time;
		INT uid;
		INT auid;
		INT unitid;
} InitList;

map<INT, InitList> graphInitList;
map<INT, vector<GraphList> > graphList;
stack<string> graphEdge;

typedef struct {
		string time;
		INT pid;
		INT unitid;
} Process;

/* 
	* Proc - Proc dep. Only for process, not thread
	* Proc - file dep. If proc is <F5>
	*/

INT num_process = 0;
INT num_file = 0;
INT num_socket = 0;
INT num_edge = 0;


void graph_init()
{
#ifdef WITHOUT_UNIT
		if(is_forward_search) gfp = fopen("./fs_audit.graph", "w");
		else gfp = fopen("./bs_audit.graph", "w");
#else
		if(is_forward_search) gfp = fopen("./fs_beep.graph", "w");
		else gfp = fopen("./bs_beep.graph", "w");
#endif
		fprintf(gfp, "digraph callgraph {\n\n");
}

void graph_fini()
{
		fprintf(gfp, "}");
		fprintf(gfp, "\n\n/*\nNumber of nodes : %ld\n", num_process + num_file + num_socket);
		fprintf(gfp, "\tProcess node : %ld, file node %ld, socket node %ld\n", num_process, num_file, num_socket);
		fprintf(gfp, "Number of edges : %ld\n*/", num_edge);
		fclose(gfp);
		printf("Number of nodes : %ld\n", num_process + num_file + num_socket);
		printf("\tProcess node : %ld, file node %ld, socket node %ld\n", num_process, num_file, num_socket);
		printf("Number of edges : %ld\n", num_edge);
}

map<INT, INT> procNodeList;
set<INT> fileNodeList;
set<string> socketNodeList;

INT fileNodeNum=1;
INT socketNodeNum=1;
map<string, string> fileNode;
map<INT, string> processNode;
map<string, string> socketNode;

string graph_add_processNode(INT pid, string command)
{
		map<INT,string>::iterator iter;
		iter = processNode.find(pid);
		string name;
		char temp[128];

		if(iter == processNode.end())
		{
				sprintf(temp, "P%ld\0", pid);
				name.append(temp);
				processNode.insert(pair<INT, string>(pid, name));
				fprintf(gfp, "node[shape=oval, label=\"%s\" ] %s;\n", command.c_str(), name.c_str());
				num_process++;
		} else {
				name.append(iter->second);
		}
		
		return name;
}

string graph_add_fileNode(string name)
{
		map<string, string>::iterator iter;
		iter = fileNode.find(name);

		char temp[128];
		string ret;

		if(iter == fileNode.end())
		{
				sprintf(temp, "F_%ld\0", fileNodeNum++);
				ret.append(temp);
				fileNode.insert(pair<string, string>(name, ret));
				fprintf(gfp, "node[shape=box, label=\"%s\" ] %s;\n", name.c_str(), ret.c_str());
				num_file++;
		} else {
				ret.append(iter->second);
		}
		return ret;
}

string graph_add_socketNode(string name)
{
		map<string, string>::iterator iter;
		iter = socketNode.find(name);

		char temp[128];
		string ret;

		if(iter == socketNode.end())
		{
				sprintf(temp, "S_%ld\0", socketNodeNum++);
				ret.append(temp);
				socketNode.insert(pair<string, string>(name, ret));
				fprintf(gfp, "node[shape=diamond, label=\"%s\" ] %s;\n", name.c_str(), ret.c_str());
				num_socket++;
		} else {
				ret.append(iter->second);
		}
		return ret;
}


void graph_add_edge(string from, string  to)
{
		fprintf(gfp, "%s -> %s;\n", from.c_str(), to.c_str());
		num_edge++;
}


