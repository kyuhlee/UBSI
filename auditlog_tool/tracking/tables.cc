#include <stdio.h>
#include <string>
#include "uthash.h"
#include "utlist.h"
#include "utils.h"
#include "tables.h"
#include <map>

extern bool is_init_scan;

// fp_table[n][0] = file pointer that starts a new syscal entry.
// fp_table[n][1] = size of the event (including all related events e.g,. path, cwd..)
long **fp_table; 
int fp_table_size = 0;
long user_inode = 0;
int user_pid = 0;
set<int> tainted_pid; // at lease one cluster is tainted. Need to use for fork/clone..

tainted_cluster_t *tainted_cluster;
tainted_inode_t *tainted_inode;

thread_process_t *thread2process_table;
process_table_t *process_table;

inode_table_t *inode_table;
string get_absolute_path(fd_el_t *fd_el, int num)
{
		string str;
		
		if(fd_el->num_path <= num) return string();

		if(fd_el->path[num][0] != '/') {
				return string(fd_el->cwd + "/" + fd_el->path[num]);
		}
		return string(fd_el->path[num]);
}

string get_absolute_path(string cwd, string path)
{
		string ret;

		int size = path.size();
		
		if(size > 0 && path[0] == '/') return string(path);
		
		if(cwd[cwd.size()-1] == '/') {
				ret = string(cwd);
		} else ret = string(cwd + "/");

		if(size >1 && path[0] == '.' && path[1] == '/') {
				ret.append(path.begin()+2, path.end());
		} else {
				ret.append(path);
		}

		return string(ret);
}

string merge_path(fd_el_t *el)
{
		string str;// = new string();
		debug("merge_path, el %p\n", el);

		if(el == NULL) {
				return string();
		}

		int size = 0;
		char *s;
		for(int i = 0; i < el->num_path; i++)
		{
				size += el->path[i].size();
		}
		debug("num_path = %d\n", el->num_path);
		str = string("PATH:");
		for(int i = 0; i < el->num_path; i++)
		{
				debug("path[%d] = %s\n", i, el->path[i].c_str());
				str.append(el->path[i]);
				str.append(";");
		}
		debug("str: %s\n", str.c_str());
		return str;
}

void print_fd_list(int pid, fd_table_t *ft)
{
		fd_el_t *el;
		printf("pid %d, fd %d: ", pid, ft->fd);
		DL_FOREACH(ft->fd_el, el) {
				printf("Eid %ld, socket %d, num_path %d\n", el->eid, el->is_socket, el->num_path);
				for(int i = 0; i < el->num_path; i++)
						printf("  #%d: inode %ld, path %s [type %s]\n", i, el->inode[i], el->path[i].c_str(), el->pathtype[i].c_str());
		}
		printf("\n");
}

void print_unit_cluster(int pid, unit_cluster_t* ut)
{
#ifdef DEBUG
		unit_list_t *el;
		printf("pid %d, cluster id %d: ", pid, ut->clusterid);
		DL_FOREACH(ut->list, el) {
				printf("%d-%d,", el->id.tid, el->id.unitid);
		}
		printf("\n");
#endif
}

void print_all_unit_clusters(int pid)
{
#ifdef DEBUG
		process_table_t *pt;
		unit_cluster_t *ut, *tmp;

		HASH_FIND_INT(process_table, &pid, pt);
		assert(pt);
		HASH_ITER(hh, pt->unit_cluster, ut, tmp) {
				print_unit_cluster(pid, ut);
		}
#endif
}

unit_list_t *get_unit_list(int tid, int unitid)
{
		int clusterid;
		unit_table_t *ut;
		unit_cluster_t *uc;
		process_table_t *pt = get_process_table(get_pid(tid));

		if(pt == NULL) return NULL;
		
		unit_el_t ud;
		ud.tid = tid;
		ud.unitid = unitid;

		HASH_FIND(hh, pt->unit_table, &ud, sizeof(unit_el_t), ut);
		if(ut == NULL) return NULL;

		clusterid = ut->clusterid;
		HASH_FIND_INT(pt->unit_cluster, &clusterid, uc);

		if(uc == NULL) return NULL;
		
		return uc->list;
}

fd_el_t *get_fd(process_table_t *pt, int fd, long eid)
{
		fd_table_t *ft;
		fd_el_t *elt, *last;

		//process_table_t *pt = get_process_table(pid);

		int pid = pt->pid;
		debug("get_fd %d (eid %ld), pid %d, fd_table size %u\n",fd, eid, pt->pid, HASH_COUNT(pt->fd_table));
		HASH_FIND_INT(pt->fd_table, &fd, ft);
		if(ft == NULL) {
				debug("Warning!! pid %d, fd %d, fd table is not exist.\n", pid, fd);
				return NULL;
		}
				
		last = NULL;
		DL_FOREACH(ft->fd_el, elt) {
				if(eid < elt->eid) {
						debug(" fd element: eid %ld, num_path %d, path[0] %s: return last\n", elt->eid, elt->num_path, elt->path[0].c_str());
						return last;
				}
				debug(" fd element: eid %ld, num_path %d, path[0] %s\n", elt->eid, elt->num_path, elt->path[0].c_str());
				last = elt;
		}
		if(last == NULL) {
				debug("Warning!! pid %d, fd %d, eid %ld fd list is not exist.\n", pid, fd, eid);
		}
		debug(" fd element: eid %ld, num_path %d, path[0] %s: return this\n", last->eid, last->num_path, last->path[0].c_str());
		return last;
}

process_table_t *get_process_table(int pid)
{
		process_table_t *pt;
		HASH_FIND_INT(process_table, &pid, pt);
		if(pt == NULL) {
				if(!is_init_scan) {
						debug("Warning!! process %d does not have a process table!\n", pid);
				}
				debug("Create process table: pid %d\n", pid);
				pt = (process_table_t*) malloc (sizeof(process_table_t));
				pt->pid = pid;
				pt->next_cluster_id = 1;
				pt->unit_cluster = NULL;
				pt->unit_table = NULL;
				pt->fd_table = NULL;
				HASH_ADD_INT(process_table, pid, pt);
		}
		return pt;
}

cluster_el_t get_cluster(int tid, int unitid)
{
		cluster_el_t ret;
		process_table_t *pt;
		unit_table_t *ut;

		unit_el_t ud;
		ud.tid = tid;
		ud.unitid = unitid;

		pt = get_process_table(get_pid(tid));
		HASH_FIND(hh, pt->unit_table, &ud, sizeof(unit_el_t), ut);
		
		//assert(ut);
		if(ut == NULL) {
				insert_single_unit(pt, tid, unitid);
				HASH_FIND(hh, pt->unit_table, &ud, sizeof(unit_el_t), ut);
		}
		ret.clusterid = ut->clusterid;
		ret.pid = pt->pid;

		return ret;
}

int get_pid(int tid)
{
		struct thread_process_t *ut;

		HASH_FIND_INT(thread2process_table, &tid, ut);  /* looking for parent thread's pid */
		if(ut == NULL) {
				if(is_init_scan) {
						ut = (thread_process_t*) malloc (sizeof(thread_process_t));
						ut->pid = tid;
						ut->tid = tid;
						HASH_ADD_INT(thread2process_table, tid, ut);
				} else return tid;
		}
		return ut->pid;
}

bool is_tainted_unit(process_table_t *pt, int clusterid)
{
		cluster_el_t c;
		c.pid = pt->pid;
		c.clusterid = -1;
		
		tainted_cluster_t *tc;

		HASH_FIND(hh, tainted_cluster, &c, sizeof(cluster_el_t), tc);
		if(tc != NULL) return true;

		c.clusterid = clusterid;
		HASH_FIND(hh, tainted_cluster, &c, sizeof(cluster_el_t), tc);

		if(tc == NULL) return false;
		return true;
}

bool is_tainted_unit(process_table_t *pt, int tid, int unitid)
{
		//if(tid == 49025 && unitid == 35) return true;
		//if(is_tainted_unit(pt, -1)) return true;
		int clusterid;
		unit_table_t *ut;

		unit_el_t ud;
		ud.tid = tid;
		ud.unitid = unitid;

		HASH_FIND(hh, pt->unit_table, &ud, sizeof(unit_el_t), ut);
		if(ut == NULL) {
				//printf("tid %d, unitid %d: ut is null\n", tid, unitid);
				return false;
		}
//		assert(ut);

		clusterid = ut->clusterid;
		return is_tainted_unit(pt, clusterid);
}

bool is_tainted_inode(long inode, long eid)
{
		if(inode == 0) return false;
		tainted_inode_t *ti;
		
		inode_t in = find_inode(inode, eid);
		HASH_FIND(hh, tainted_inode, &in, sizeof(inode_t), ti);

		if(ti == NULL) return false;
		return true;
}

bool taint_unit(process_table_t *pt, int clusterid, string path)
{
//		if(is_tainted_pid(pt->pid)) return false;
		if(is_tainted_unit(pt, clusterid)) return false;

		//tainted_cluster_t *tc = (tainted_cluster_t*) malloc (sizeof(tainted_cluster_t));
		tainted_cluster_t *tc = new tainted_cluster_t;
		tc->id.pid = pt->pid;
		tc->id.clusterid = clusterid;
		tc->path = string(path);

		debugtaint("Taint_unit: pid %d, clusterid %d, path %s\n", pt->pid, clusterid, path.c_str());
		HASH_ADD(hh, tainted_cluster, id, sizeof(cluster_el_t), tc);
		tainted_pid.insert(pt->pid);

		return true;
}

bool taint_unit(process_table_t *pt, int tid, int unitid, string path)
{
//		if(is_tainted_unit(pt, tid, unitid)) return false;
		unit_table_t *ut;

		unit_el_t ud;
		ud.tid = tid;
		ud.unitid = unitid;

		HASH_FIND(hh, pt->unit_table, &ud, sizeof(unit_el_t), ut);
		
		if(ut == NULL) {
				insert_single_unit(pt, tid, unitid);
				HASH_FIND(hh, pt->unit_table, &ud, sizeof(unit_el_t), ut);
		}
		int clusterid = ut->clusterid;
		
		if(is_tainted_unit(pt, clusterid)) return false;

		//tainted_cluster_t *tc = (tainted_cluster_t*) malloc (sizeof(tainted_cluster_t));
		tainted_cluster_t *tc = new tainted_cluster_t;
		tc->id.pid = pt->pid;
		tc->id.clusterid = clusterid;
		tc->path = string(path);

		debugtaint("Taint_unit: pid %d (tid %d, unitid%d), clusterid %d, path %s\n", pt->pid, tid, unitid, clusterid, path.c_str());
		HASH_ADD(hh, tainted_cluster, id, sizeof(cluster_el_t), tc);
		tainted_pid.insert(pt->pid);

		return true;
}

bool is_tainted_pid(int pid)
{
		int spid = get_pid(pid);
		if(tainted_pid.find(spid) != tainted_pid.end()) return true;
		return false;
}

bool taint_all_units_in_pid(int pid, string path)
{
		int spid = get_pid(pid);
		
		if(is_tainted_unit(get_process_table(pid), -1)) return false;
		//if(is_tainted_pid(spid)) return false;

		//tainted_cluster_t *tc = (tainted_cluster_t*) malloc (sizeof(tainted_cluster_t));
		tainted_cluster_t *tc = new tainted_cluster_t;
		tc->id.pid = spid;
		tc->id.clusterid = -1;
		tc->path = string(path);

		HASH_ADD(hh, tainted_cluster, id, sizeof(cluster_el_t), tc);
		tainted_pid.insert(spid);

		return true;;

}

bool taint_inode(long inode, long eid, string path)
{
		if(inode == 0) return false;
		if(is_tainted_inode(inode, eid)) return false;

		inode_t id = find_inode(inode, eid);

		tainted_inode_t *in;
		
		//inode_t in;
		//in.inode = inode;

		//in = (tainted_inode_t*)malloc(sizeof(tainted_inode_t));
		in = new tainted_inode_t;
		in->inode.inode = inode;
		in->inode.created_eid = id.created_eid;
		in->name = string(path);

		debugtaint("Taint inode %ld\n", inode);
		HASH_ADD(hh, tainted_inode, inode, sizeof(inode_t), in);
		return true;
}

map<string, int> tainted_socket;
int tainted_socket_num = 1;
int taint_socket(string name)
{
		map<string, int>::iterator it;
		it = tainted_socket.find(name);
		if(it != tainted_socket.end()) return it->second;

		tainted_socket.insert(pair<string, int>(name, tainted_socket_num++));
		return tainted_socket_num-1;
}

set<string> edge_list; 

void edge_proc_to_file(int tid, int unitid, long inode, long eid)
{
		char tmp[1024];
		cluster_el_t cl = get_cluster(tid, unitid);
		inode_t id = find_inode(inode, eid);
		
		sprintf(tmp, "P%d_%d -> F%ld_%ld", cl.pid, cl.clusterid, id.inode, id.created_eid);

		edge_list.insert(string(tmp));
}

void edge_file_to_proc(int tid, int unitid, long inode, long eid)
{
		char tmp[1024];
		cluster_el_t cl = get_cluster(tid, unitid);
		inode_t id = find_inode(inode, eid);

		sprintf(tmp, "F%ld_%ld -> P%d_%d", id.inode, id.created_eid, cl.pid, cl.clusterid);

		edge_list.insert(string(tmp));
}

void edge_proc_to_proc(int from_tid, int from_unitid, int to_pid)
{
		// traverse tainted_cluster and add edge from to all to_pid.
		char tmp[1024];
		cluster_el_t cl = get_cluster(from_tid, from_unitid);
		tainted_cluster_t *tt, *tp;

		HASH_ITER(hh, tainted_cluster, tt, tp) {
				if(tt->id.pid == to_pid) {
						sprintf(tmp, "P%d_%d -> P%d_%d", cl.pid, cl.clusterid, tt->id.pid, tt->id.clusterid);
						edge_list.insert(string(tmp));
				}
		}
}

void edge_socket_to_proc(int tid, int unitid, int socket)
{
		char tmp[1024];
		cluster_el_t cl = get_cluster(tid, unitid);
		sprintf(tmp, "S%d -> P%d_%d", socket, cl.pid, cl.clusterid);

		edge_list.insert(string(tmp));
}

void edge_proc_to_socket(int tid, int unitid, int socket)
{
		char tmp[1024];
		cluster_el_t cl = get_cluster(tid, unitid);
		sprintf(tmp, "P%d_%d -> S%d", cl.pid, cl.clusterid, socket);

		edge_list.insert(string(tmp));
}

inode_t find_inode(long inode, long eid)
{
		inode_table_t *it;
		inode_t ret;
		
		HASH_FIND(hh, inode_table, &inode, sizeof(long), it);
		if(it == NULL) {
				//printf("Inode %ld is not in the table.\n", inode);
				//assert(0);
				ret.inode = inode;
				ret.created_eid = 0;

				return ret;
		}
	
		for(vector<inode_el_t>::iterator iit = it->list.begin(); iit != it->list.end(); iit++)
		{
				if(iit->created_eid <= eid && (iit->deleted_eid == 0 || iit->deleted_eid >= eid))
				{
						ret.inode = inode;
						ret.created_eid = iit->created_eid;

						return ret;
				}
		}
		fprintf(stderr, "inode %ld, eid %ld is not valid..\n", inode, eid);
 	assert(0);
		ret.inode = inode;
		ret.created_eid = 0;
		
		return ret;
}


long check_inode_list(long inode, string *path)
{
		inode_table_t *it;
		vector<inode_el_t>::iterator iit;
		
		HASH_FIND(hh, inode_table, &inode, sizeof(long), it);
		if(it == NULL) {
				printf("Inode %ld is not in the table.\n", inode);
				return -1;
		}
		if(it->list.size() == 1) {
				iit = it->list.begin();
				printf("User Tainted Inode: Path: %s, Created (eid %ld): %ld(%s), Deleted (eid %ld): %ld(%s)\n", 
						iit->name.c_str(),
						iit->created_eid, iit->created_time,
						convert_time(iit->created_time, iit->created_time_mil).c_str(),
						iit->deleted_eid, iit->deleted_time,
						convert_time(iit->deleted_time, iit->deleted_time_mil).c_str());
				
				*path = string(iit->name);
				return it->list.back().created_eid;
		}

		printf("\n **More than two files have Inode %ld. Select the number:\n", inode);
		
		int i = 1;
		for(iit = it->list.begin(); iit != it->list.end(); iit++)
		{
				printf("[%d]: Path: %s, Created (eid %ld): %ld(%s), Deleted (eid %ld): %ld(%s)\n", 
						i, iit->name.c_str(),
						iit->created_eid, iit->created_time,
						convert_time(iit->created_time, iit->created_time_mil).c_str(),
						iit->deleted_eid, iit->deleted_time,
						convert_time(iit->deleted_time, iit->deleted_time_mil).c_str());
				i++;
		}

		int sel;
		fscanf(stdin, "%d", &sel);
		while(sel  < 1 || sel > it->list.size()) {
				printf("User selected number is not valid: %d\n", sel);
				fscanf(stdin, "%d", &sel);
		}
		
		sel--;
		printf("User Tainted Inode: Path: %s, Created (eid %ld): %ld(%s), Deleted (eid %ld): %ld(%s)\n", 
						it->list[sel].name.c_str(),
						it->list[sel].created_eid, it->list[sel].created_time,
						convert_time(it->list[sel].created_time, it->list[sel].created_time_mil).c_str(),
						it->list[sel].deleted_eid, it->list[sel].deleted_time,
						convert_time(it->list[sel].deleted_time, it->list[sel].deleted_time_mil).c_str());

		*path = string(it->list[sel].name);
		return it->list[sel].created_eid;
}

void insert_inode_table(char *buf, long eid)
{
		char *ptr;
		long inode;
		string type, path;
		inode_table_t *it;
		set<inode_el_t>::reverse_iterator rit;
		time_t time;
		unsigned int mil;

		extract_long(buf, " inode=", 7, &inode);
		extract_time(buf, &time, &mil);
		
		HASH_FIND_LONG(inode_table, &inode, it);
		if(it == NULL)
		{
				it = new inode_table_t;
				it->inode = inode;

				HASH_ADD(hh, inode_table, inode, sizeof(long),  it);
		}
		
		if(strstr(buf, "nametype=NORMAL")) {
				if((!it->list.empty())) return;

				inode_el_t el;
				el.created_time = el.created_time_mil = 0;
				el.deleted_time = el.deleted_time_mil = 0;
				el.name = extract_string(buf, " name=", 6);
				el.created_eid = 0;
				el.deleted_eid = 0;

				it->list.push_back(el);

		} else if(strstr(buf, "nametype=CREATE")) {
				if(!it->list.empty()) {
						it->list.back().deleted_time = time;
						it->list.back().deleted_time_mil = mil;
						it->list.back().deleted_eid = eid;
				}
				inode_el_t el;
				el.created_time = time;
				el.created_time_mil = mil;
				el.deleted_time = el.deleted_time_mil = 0;
				el.name = extract_string(buf, " name=", 6);
				el.created_eid = eid;
				el.deleted_eid = 0;

				it->list.push_back(el);
		} else if(strstr(buf, "nametype=DELETE")) {
				if(it->list.empty()) return;

				it->list.back().deleted_time = time;
				it->list.back().deleted_time_mil = mil;
				it->list.back().deleted_eid = eid;
		}
}

void print_fp_table()
{
		return;
		printf("fp_table_size %d\n", fp_table_size);
		for(int i = 0; i < fp_table_size; i++)
		{
				printf("[%d]: begin %ld, size %ld\n", i, fp_table[i][0], fp_table[i][1]);
		}
}

void generate_fp_table(FILE *fp)
{
		int i;
		char *ptr;
		long fend, fcur;
		char buf[1048576], buf2[1048576];
		long sys_eid, eid;

		printf("\n(1/4) Generate file pointer table (# of syscall: %ld).\n", num_syscall);
		
		num_syscall++;
		fseek(fp, 0L, SEEK_END);
		fend = ftell(fp);
		fseek(fp, 0L, SEEK_SET);
		loadBar(0, fend, 10, 50);

		fp_table = (long**)malloc(sizeof(long*) * num_syscall);
		for(i = 0; i < num_syscall; i++)
		{
				fp_table[i] = (long*) malloc(sizeof(long) * 2);
		}
		
		i = sys_eid = eid = 0;
		fcur = 0;

		fgets(buf, 1048576, fp);
		while(!feof(fp)) 
		{
				ptr = strstr(buf, ":");
				if(ptr == NULL) {
						if(sys_eid) {
								fp_table[fp_table_size][1] = fcur-fp_table[fp_table_size][0];
								fp_table_size++;
						}
						sys_eid = eid = 0;
						fcur = ftell(fp);
						fgets(buf, 1048576, fp);
						continue;
				}

				eid = strtol(ptr+1, NULL, 10);

				if(strncmp(buf, "type=SYSCALL",12) == 0) {
						if(sys_eid) {
								//fp_table[fp_table_size][1] = fcur;
								fp_table[fp_table_size][1] = fcur-fp_table[fp_table_size][0];
								fp_table_size++;
						}
						fp_table[fp_table_size][0] = fcur;
						sys_eid = eid;
				}

				if(strncmp(buf, "type=PATH",9) == 0) {
						insert_inode_table(buf, eid);
				}

				if(i++ > 10000) {
						loadBar(fcur, fend, 10, 50);
						i = 0;
			 }
				fcur = ftell(fp);
				fgets(buf, 1048576, fp);
		}
		
		if(sys_eid) {
				fp_table[fp_table_size][1] = fcur-fp_table[fp_table_size][0];
				debugnow("fp_table[%d]: start %ld, last %ld\n", fp_table_size, fp_table[fp_table_size][0], fp_table[fp_table_size][1]);
				fp_table_size++;
		}
}

void init_table()
{
		thread2process_table = NULL;
		process_table = NULL;
		tainted_cluster = NULL;
		tainted_inode = NULL;
		inode_table = NULL;
}
