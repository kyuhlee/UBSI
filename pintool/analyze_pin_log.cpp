#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <map>
#include <set>
#include <stack>
#include <vector>
#include "intervalTree/interval.H"
#include <assert.h>

using namespace std;

//#define ANALYZE_MEM
#define NDEBUG
#define NDEBUG_MEM

#ifdef NDEBUG
#define debug(M, ...)
#else
#define debug(M, ...) fprintf(stderr, "DEBUG %s:%d: " M, __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#ifdef NDEBUG_MEM
#define debug_mem(M, ...)
#else
#define debug_mem(M, ...) fprintf(stderr, "DEBUG %s:%d: " M, __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#define MAX_THREAD 1024
#define MAX_LOOP_DEPTH 2
#define MIN_ITERATION 3

#define LOWADDR  0x7f1994bf0000
#define HIGHADDR 0x7f199e45bdd3
enum TYPE {
		LOOP_ENTRY,
		LOOP_EXIT,
		WRITE,
		READ,
		SYSCALL,
		MALLOC,
		FREE,
		REALLOC
};

typedef struct {
		TYPE type;
		unsigned long long time;
		int tid;
		int num;
		int numOfLoopSyscall;
		int id;
		uint64_t ip;
		uint64_t addr; // for mem read/write
		uint64_t size;
		uint64_t addrSrc; // for realloc
		int iterNum;
} Entry;

typedef struct {
		int iter;
		int firstAppear;
		int lastAppear;
		int syscall;
} LoopEntry;

typedef struct {
		map<int, int> readBy; // <unit_num, count>
		map<int, int> writtenBy;  // <unit_num, count>
		set<int> readTid;
		set<int> writeTid;
		set<int> readLoopId;
		set<int> writeLoopId;
} MemEntry;

map<int, Entry> log;
map<int, Entry> loop[MAX_THREAD];
map<int, LoopEntry> selectedLoops[MAX_THREAD]; // <loop_id, {# of iteration, # of syscalls}>
map<int, MemEntry> memMap; // <memId, >
map<int, int> unitId2LoopId; // <unit_num, loop_id> 
map<int, int> unitId2Tid; // <unit_num, tid> 

int numOfSyscall[MAX_THREAD];
int numOfLoopSyscall[MAX_THREAD];
int maxTid = 0;

void print_progress(float progress)
{
		int i;
		int barWidth = 70;
		fprintf(stdout, "\r[");
		int pos = barWidth * progress;
		for (i = 0; i < barWidth; ++i) {
				if (i < pos) fprintf(stdout,"=");
				else if (i == pos) fprintf(stdout,">");
				else fprintf(stdout," ");
		}
		fprintf(stdout,"] %.1f%%", (float)(progress * 100.0));
		fflush(stdout);
		if(progress >= 1) fprintf(stdout,"\n");
}

bool read_trace(const char *name)
{
		FILE *fp;
		char tmp[512];

		fp = fopen(name, "r");
		if(fp == NULL) {
				fprintf(stdout, "File open error: %s\n", name);
				return false;
		}
		
		unsigned long long processed = 0;
		unsigned long long total;
		float progress = 0;
		int i = 0;
		fseek(fp, 0L, SEEK_END);
		total = ftell(fp);
		fseek(fp, 0L, SEEK_SET);

		char type[2];
		int no = 0;

		unsigned long long ts;
		unsigned long long seq = 0;
		char line[512];
		multimap<unsigned long long, string> records;

		fprintf(stdout, "Reading input file %s...\n", name);
		while(fgets(line, 512, fp))
		{
				processed+=strlen(line);
				progress = (float)((float)processed / (float)total);
				sscanf(line, "%llu: %[^\n]", &ts, tmp);
				records.insert(pair<unsigned long long, string>(ts, tmp));
				if(i++ % 100000 == 0) print_progress(progress);

				//records.insert(pair<unsigned long long, string>(seq++, tmp));
		}
		print_progress(1);

		multimap<unsigned long long, string>::iterator iter = records.begin();
		fprintf(stdout, "Inserting records into a map structure...\n");
		total = records.size();
		i = 0;
		for (; iter != records.end(); ++iter)
		{
				//printf("%llu: %s\n", iter->first, iter->second.c_str());

				const string& str = iter->second;
				Entry ent;

				sscanf(str.c_str(), "[%d] %s", &ent.tid, type);

				if(maxTid < ent.tid) {
						maxTid = ent.tid;
						if(maxTid >= MAX_THREAD) {
								fprintf(stdout, "Increase MAX_THREAD! : maxTid = %d\n", maxTid);
								return false;
						}
				}
				
				ent.time = iter->first;
				if(strncmp(type, "LE", 2) == 0) {
						ent.type = LOOP_ENTRY;
				} else if(strncmp(type, "LX", 2) == 0) {
						ent.type = LOOP_EXIT;
				} else if(strncmp(type, "WR", 2) == 0) {
						ent.type = WRITE;
				} else if(strncmp(type, "RD", 2) == 0) {
						ent.type = READ;
				} else if(strncmp(type, "SC", 2) == 0) {
						ent.type = SYSCALL;
						numOfSyscall[ent.tid]++;
				} else if(strncmp(type, "MA", 2) == 0) {
						ent.type = MALLOC;
				} else if(strncmp(type, "RA", 2) == 0) {
						ent.type = REALLOC;
				} else if(strncmp(type, "FR", 2) == 0) {
						ent.type = FREE;
				} else {
						fprintf(stdout, "TYPE ERROR: %s\n", str.c_str());
						return false;
				}

				no++;
				ent.num = no;
				if(ent.type == LOOP_ENTRY || ent.type == LOOP_EXIT || ent.type == SYSCALL) {
						ent.numOfLoopSyscall = ++numOfLoopSyscall[ent.tid];
				}

				if(ent.type == LOOP_ENTRY || ent.type == LOOP_EXIT || ent.type == SYSCALL)
				{
						if(sscanf(str.c_str(), "[%d] %s ip %lx id %d", &ent.tid, type, &ent.ip, &ent.id) < 4) {
								fprintf(stdout, "Read trace failed! : %s\n", str.c_str());	
								return false;
						}
						loop[ent.tid].insert(pair<int, Entry> (no, ent));
				} else if(ent.type == WRITE || ent.type == READ || ent.type == MALLOC || ent.type == FREE) {
						if(sscanf(str.c_str(), "[%d] %s ip %lx id %d addr %lx size %ld", &ent.tid, type, &ent.ip, &ent.id, &ent.addr, &ent.size) < 6) {
								fprintf(stdout, "Read trace failed! : %s\n", str.c_str());	
								return false;
						}
						if(ent.size < 4096) continue; //KYU
				} else if(ent.type == REALLOC) {
						if(sscanf(str.c_str(), "[%d] %s ip %lx id %d addr %lx size %ld addr_src %lx", &ent.tid, type, &ent.ip, &ent.id, &ent.addr, &ent.size, &ent.addrSrc) < 7) {
								fprintf(stdout, "Read trace failed! : %s\n", str.c_str());	
								return false;
						}
				}
				log.insert(pair<int, Entry> (no, ent));
				if(i++ % 100000 == 0) {
						print_progress((float)((float)i / (float)total));
				}
		}
		print_progress(1);
		return true;
}

void print_preprocessed(char *name)
{
		map<int, Entry>::iterator it;
		// output just like input file.
		char fname[256];
		sprintf(fname, "%s.preprocessed", name);
		FILE *fp = fopen(fname, "w");
		for(it = log.begin(); it != log.end(); it++)
		{
				fprintf(fp, "%llu: [%d] ", it->second.time, it->second.tid);
				if(it->second.type == LOOP_ENTRY) fprintf(fp, "LE ");
				else if(it->second.type == LOOP_EXIT) fprintf(fp, "LX ");
				else if(it->second.type == WRITE) fprintf(fp, "WR ");
				else if(it->second.type == READ) fprintf(fp, "RD ");
				else if(it->second.type == MALLOC) fprintf(fp, "MA ");
				else if(it->second.type == REALLOC) fprintf(fp, "RA ");
				else if(it->second.type == FREE) fprintf(fp, "FR ");
				else if(it->second.type == SYSCALL) fprintf(fp, "SC ");

				if(it->second.type == LOOP_ENTRY || it->second.type == LOOP_EXIT || it->second.type == SYSCALL) {
						fprintf(fp, "ip %lx id %d\n", it->second.ip, it->second.id);
				} else if(it->second.type == REALLOC) {
						fprintf(fp, "ip %lx id %d addr %lx size %ld addr_src %lx\n", it->second.ip, it->second.id, it->second.addr, it->second.size, it->second.addrSrc);
				} else if(it->second.type == READ || it->second.type == WRITE || it->second.type == FREE) {
						fprintf(fp, "ip %lx id %d addr %lx size %ld\n", it->second.ip, it->second.id, it->second.addr, it->second.size);
				}
		}
		fclose(fp);
}

void print_map(int tid, int flag)
{
		map<int, Entry>::iterator it;

		if(flag == 1) {
				printf("PRINT LOG: %d ENTRIES\n", (int)log.size());
				for(it = log.begin(); it != log.end(); it++)
				{
						printf("[%d] %d ", it->second.tid, it->second.num);
						if(it->second.type == LOOP_ENTRY) printf("LE ");
						else if(it->second.type == LOOP_EXIT) printf("LX ");
						else if(it->second.type == WRITE) printf("WR ");
						else if(it->second.type == READ) printf("RD ");
						else if(it->second.type == SYSCALL) printf("SC ");
						else if(it->second.type == MALLOC) printf("MA ");
						else if(it->second.type == REALLOC) printf("RA ");
						else if(it->second.type == FREE) printf("FR ");

						printf(" ip %lx id %d num %d\n", it->second.ip, it->second.id, it->second.num);
				}
		}

		if(flag == 2) {
				printf("PRINT LOOP: %d ENTRIES\n", (int)loop[tid].size());
				for(it = loop[tid].begin(); it != loop[tid].end(); it++)
				{
						printf("%d ", it->second.num);
						if(it->second.type == LOOP_ENTRY) printf("LE ");
						else if(it->second.type == LOOP_EXIT) printf("LX ");
						else if(it->second.type == SYSCALL) printf("SC ");

						printf(" id %d ip %lx\n", it->second.id, it->second.ip);
				}
		}

}

void delete_entry(int tid, int no)
{
		debug("DELETE : %d\n", no);
		log.erase(no);
		loop[tid].erase(no);
}

void loop_pairing(int tid)
{
		debug("======= Loop Entry/Exit pairing ======\n");
		stack<Entry> loop_stack;
		stack<int> to_delete;
		map<int, Entry>::iterator it;

		for(it = loop[tid].begin(); it != loop[tid].end(); it++)
		{
				if(it->second.type == LOOP_ENTRY) loop_stack.push(it->second);
				else if(it->second.type == LOOP_EXIT) {
						if(loop_stack.size() == 0) {
								debug("Encounter exit(id %d, num %d), but stack is empty.\n", it->second.id, it->second.num);
								continue;
						}

						Entry ent;
						if(loop_stack.size() > 0) ent = loop_stack.top();
						else continue;
						if(ent.id == it->second.id) loop_stack.pop();
						else if(loop_stack.size() > 0) {
								while(ent.id != it->second.id) {
										debug("Stack(%ld) top is not match to the loop exit, top %d(no %d), exit %d(no %d), remove top\n", loop_stack.size(), ent.id, ent.num, it->second.id, it->second.num);
										to_delete.push(ent.num);
										loop_stack.pop();
										if(loop_stack.size() == 0) break;
										ent = loop_stack.top();
								}
								if(loop_stack.size() > 0) {
										loop_stack.pop();
										debug("Match: top %d(no %d), exit %d(no %d), stacksize %ld\n", ent.id, ent.num, it->second.id, it->second.num, loop_stack.size());
								}
						}
				}
		}
		// Remove remaining loop entries in stack.
		while(loop_stack.size() > 0)
		{
				Entry ent = loop_stack.top();
				delete_entry(tid, ent.num);
				loop_stack.pop();
		}

		while(to_delete.size()) {
				delete_entry(tid, to_delete.top());
				to_delete.pop();
		}
}

void remove_nested_loops(int tid)
{
		debug("===== Remove nested(> %d depth) loops=====\n", MAX_LOOP_DEPTH);
		stack<Entry> loop_stack;
		stack<int> to_delete;
		map<int, Entry>::iterator it;

		// Delete nested loops
		for(it = loop[tid].begin(); it != loop[tid].end(); it++)
		{
				debug("# %d\n", it->second.num);
				if(it->second.type == LOOP_ENTRY) loop_stack.push(it->second);
				else if(it->second.type == LOOP_EXIT) {
						if(loop_stack.size() > MAX_LOOP_DEPTH) {
								Entry ent = loop_stack.top();
								debug("Loop depth %d, Delete Entry %d, Exit %d\n", (int)loop_stack.size(), ent.num, it->second.num);
								to_delete.push(ent.num);
								to_delete.push(it->second.num);
						} 
						if(loop_stack.size() > 0) loop_stack.pop();
				}
		}

		while(to_delete.size()) {
				delete_entry(tid, to_delete.top());
				to_delete.pop();
		}
}

typedef struct {
		int num;
		int id;
		int syscall;
} _loop;

void detecting_loop_with_syscall(int tid)
{
		stack<_loop> loop_stack;
		stack<int> to_delete;
		//insert remaining loops into loop_set. We will use it to detect loops with syscalls
		for(map<int, Entry>::iterator it = loop[tid].begin(); it != loop[tid].end(); it++)
		{
				if(it->second.type == LOOP_ENTRY) {
						map<int,LoopEntry>::iterator it2 = selectedLoops[tid].find(it->second.id);
						if(it2 == selectedLoops[tid].end()) {
								LoopEntry l = {1,0,0,0};
								selectedLoops[tid].insert(pair<int, LoopEntry>(it->second.id, l));
						}
						else it2->second.iter++;
				}
		}

		for(map<int, Entry>::iterator it = loop[tid].begin(); it != loop[tid].end(); it++)
		{
				if(it->second.type == LOOP_ENTRY) {
						_loop l = {it->second.num, it->second.id, 0};
						loop_stack.push(l);
				} else if(it->second.type == LOOP_EXIT) {
						if(loop_stack.size() == 0) {
								debug("Loop pairing failed!\n");
								continue;
								//exit(0);
						}
						int syscall_called = loop_stack.top().syscall;
						if(syscall_called == 0) {
								debug("Loop %d [%d,%d] does not have syscalls. Delete\n", loop_stack.top().id, loop_stack.top().num, it->second.num);
								selectedLoops[tid].erase(loop_stack.top().id);
						} else {
								debug("Loop %d [%d,%d] called syscalls %d times.\n", loop_stack.top().id, loop_stack.top().num, it->second.num, syscall_called);
								map<int,LoopEntry>::iterator it2 = selectedLoops[tid].find(loop_stack.top().id);
								if(it2 != selectedLoops[tid].end()) {
										it2->second.lastAppear = it->second.numOfLoopSyscall;
										if(it2->second.firstAppear == 0) it2->second.firstAppear = it->second.numOfLoopSyscall;
										it2->second.syscall += syscall_called;
								}
						}
						loop_stack.pop();
						if(loop_stack.size() > 0) loop_stack.top().syscall += syscall_called;
				} else if(it->second.type == SYSCALL) {
						if(loop_stack.size() > 0) loop_stack.top().syscall++;
				}
		}

		for(map<int, LoopEntry>::iterator it = selectedLoops[tid].begin(); it != selectedLoops[tid].end(); it++)
		{
				if(it->second.iter < MIN_ITERATION) selectedLoops[tid].erase(it);
		}
}

void remove_unselected_loops()
{
		stack<int> to_delete;
		stack<int> to_delete_loop;
		for(int tid = 0; tid <= maxTid; tid++) {
				for(map<int, LoopEntry>::iterator it = selectedLoops[tid].begin(); it != selectedLoops[tid].end(); it++)
				{
						// Some heuristics..
						if((it->second.lastAppear - it->second.firstAppear) * 3 < numOfLoopSyscall[tid]) {
								debug("Loop id %d DELETED!! : %d iterations, %d/%d syscall called inside the loop. First appeared: %d, Last appeared: %d, total log entries %d\n", it->first, it->second.iter, it->second.syscall, numOfSyscall[tid], it->second.firstAppear, it->second.lastAppear, numOfLoopSyscall[tid]);
								to_delete_loop.push(it->first);
								//continue;
						}
						if(it->second.syscall * 5 < numOfSyscall[tid]) {
								debug("Loop id %d DELETED2!! : %d iterations, %d/%d syscall called inside the loop. First appeared: %d, Last appeared: %d, total log entries %d\n", it->first, it->second.iter, it->second.syscall, numOfSyscall[tid], it->second.firstAppear, it->second.lastAppear, numOfLoopSyscall[tid]);
								to_delete_loop.push(it->first);
								//	continue;
						}
				}

				debug("Delete: %ld loops\n", to_delete_loop.size());
				while(to_delete_loop.size()) {
						selectedLoops[tid].erase(to_delete_loop.top());
						debug("Delete loop %d\n", to_delete_loop.top());
						to_delete_loop.pop();
				}
		}

		for(map<int, Entry>::iterator it = log.begin(); it != log.end(); it++)
		{
				if(it->second.type == LOOP_ENTRY || it->second.type == LOOP_EXIT)
				{
						map<int,LoopEntry>::iterator it2 = selectedLoops[it->second.tid].find(it->second.id);
						if(it2 == selectedLoops[it->second.tid].end()) {
								to_delete.push(it->first);
						}
				}
				if(it->second.type == SYSCALL) to_delete.push(it->first);
		}

		while(to_delete.size()) {
				log.erase(to_delete.top());
				to_delete.pop();
		}

}

void analyze_loop(int tid)
{
		//fprintf(stderr, "Analyzing loops.. thread #%d\n", tid);
		loop_pairing(tid);

		//print_map(0,1);
		remove_nested_loops(tid);

		debug("==============\n");
		//print_map(tid, 2);
		detecting_loop_with_syscall(tid);
}

void preprocess_memory()
{
		ITNode *ITRoot = NULL;
		int memId = 1;
		stack<int> to_delete;
		Interval t, *res;

		int i = 0;
		int total = log.size();
		fprintf(stdout, "Preprocessing memory accesses..\n");
		for(map<int, Entry>::iterator it = log.begin(); it != log.end(); it++)
		{
				i++;
				if(i % 100000 == 0) print_progress((float)((float)i / (float)total));
				if(it->second.type == MALLOC) {
						t.low = it->second.addr;
						t.high = it->second.addr+it->second.size;
						t.id = it->second.id;
						t.active = true;
						debug_mem("MA %llx, %d\n", it->second.addr, it->second.size);
						ITRoot = IT_insert(ITRoot, t);
						to_delete.push(it->first);
				} else if(it->second.type == FREE) {
						//if(IT_erase(ITRoot, it->second.addr) == false)  {
						//fprintf(stdout, "IT_erase failed. num %d, addr = %lx\n", it->first, it->second.addr);
						//}
						to_delete.push(it->first);
				} else if(it->second.type == REALLOC) {
						IT_erase(ITRoot, it->second.addrSrc);

						t.low = it->second.addr;
						t.high = it->second.addr+it->second.size;
						t.id = memId++;
						t.active = true;
						ITRoot = IT_insert(ITRoot, t);
						debug_mem("MA %llx, %d\n", it->second.addr, it->second.size);
						to_delete.push(it->first);
				} else if(it->second.type == READ) {
						//continue;
						t.low = it->second.addr;
						t.high = it->second.addr+it->second.size;
						t.id = 0;
						t.active = true;

						res = IT_overlapSearch(ITRoot, t);
						if(res != NULL) {
								it->second.id = res->id;
							 debug_mem("READ valid: %llx, id %d\n", it->second.addr, it->second.id);
						} else {
								debug_mem("READ delete: %llx\n", it->second.addr);
								to_delete.push(it->first);
						}
				} else if(it->second.type == WRITE) {
						//continue;
						t.low = it->second.addr;
						t.high = it->second.addr+it->second.size;
						t.id = 0;
						t.active = true;

						res = IT_overlapSearch(ITRoot, t);
						if(res != NULL) {
								it->second.id = res->id;
								debug_mem("WRITE valid: %llx, id %d\n", it->second.addr, it->second.id);
						} else {
								debug_mem("WRITE delete: %llx\n", it->second.addr);
								to_delete.push(it->first);
						}
				}
		}
		print_progress(1);

		while(to_delete.size()) {
				log.erase(to_delete.top());
				to_delete.pop();
		}
}

void print_memMap()
{
		int total = 0;
		printf("print_memMap\n");
		for(map<int, MemEntry>::iterator it = memMap.begin(); it != memMap.end(); it++)
		{
				if(it->second.readBy.empty() || it->second.writtenBy.empty()) continue;
				printf("MemId: %d, (loopId, iterNum[tid]) - X times accessed\n", it->first);
				printf("    ReadBy: ");
				for(map<int,int>::iterator it2 = it->second.readBy.begin(); it2 != it->second.readBy.end(); it2++)
				{
						printf("        (%d,%d[%d])-%d times\n", unitId2LoopId[it2->first], it2->first, unitId2Tid[it2->first], it2->second);  
				}
				printf("\n    WrittenBy: ");
				for(map<int,int>::iterator it2 = it->second.writtenBy.begin(); it2 != it->second.writtenBy.end(); it2++)
				{
						printf("      (%d,%d[%d])-%d times\n", unitId2LoopId[it2->first], it2->first, unitId2Tid[it2->first], it2->second);  
				}
				printf("\n");
		}
		printf("Print_map: total mem object %d\n", total);
}


int insert_units_into_memMap(int tid, vector<Entry> & v, int type, int memId)
{
		debug("insert_units_into_memMap, tid %d, type %d, memId %d\n");
		// type: 1.read, 2.write
		if(v.size() == 0) return 0;

		map<int, MemEntry>::iterator mit;


		if((mit = memMap.find(memId)) == memMap.end()) {
				MemEntry m;
				memMap.insert(pair<int, MemEntry>(memId, m));
		}

		mit = memMap.find(memId);

		map<int,int>::iterator it2;
		int iter;

		// For nested unit loops
		for(vector<Entry>::iterator vit = v.begin(); vit != v.end(); vit++)
		{
				iter = vit->iterNum;
				if(type == 1) {
						it2 = mit->second.readBy.find(v.back().iterNum);
						if(it2 == mit->second.readBy.end()) {
								mit->second.readBy.insert(pair<int,int>(v.back().iterNum, 1));
								mit->second.readTid.insert(vit->tid);
								mit->second.readLoopId.insert(vit->id);
						} else {
								it2->second++;
						}
				} else if(type == 2) {
						it2 = mit->second.writtenBy.find(v.back().iterNum);
						if(it2 == mit->second.writtenBy.end()) {
								mit->second.writtenBy.insert(pair<int,int>(v.back().iterNum, 1));
								mit->second.writeTid.insert(vit->tid);
								mit->second.writeLoopId.insert(vit->id);
						} else {
								it2->second++;
						}
				}
		}
}

void prepare_memMap()
{
		fprintf(stdout, "Preparing the memory map..\n");
		vector<Entry> loop_vector[MAX_THREAD];
		int iterNum = 1;

		//memMap
		int total = log.size();
		int i = 0;
		map<int, MemEntry>::iterator mit;
		for(map<int, Entry>::iterator it = log.begin(); it != log.end(); it++)
		{
				if(i % 100000 == 0) print_progress((float)((float)i / (float)total));
				int tid = it->second.tid;
				//printf("tid = %d\n",tid);
				assert(tid < MAX_THREAD);
				if(it->second.type == LOOP_ENTRY) {
						it->second.iterNum = iterNum;
						loop_vector[tid].push_back(it->second);
						unitId2LoopId[iterNum] = it->second.id;
						unitId2Tid[iterNum] = tid;
						iterNum++;
				} else if(it->second.type == LOOP_EXIT) {
						if(loop_vector[tid].size() == 0) continue;
						if(loop_vector[tid].back().id != it->second.id) {
								debug("Loop pair is not MATCH! top : %d, exit : %d\n", loop_vector[tid].back().id, it->second.id);
						}
						loop_vector[tid].pop_back();
				} else if(it->second.type == READ) {
						insert_units_into_memMap(tid, loop_vector[tid], 1, it->second.id);
				} else if(it->second.type == WRITE) {
						insert_units_into_memMap(tid, loop_vector[tid], 2, it->second.id);
				} else {
						fprintf(stdout, "Unexpected type: %d, id %d\n", it->second.type, it->second.id);

				}
		}
		print_progress(1);
}


/*
			If the memory block (mallocked) is accessed by
			1) Different units from the same loop (same code) --> Low-level dependence: erase
			2) Different units from different loops --> Workflow dependence
			*/

void analyze_memMap()
{

		stack<int> to_delete;
		for(map<int, MemEntry>::iterator it = memMap.begin(); it != memMap.end(); it++)
		{
				if(it->second.readBy.empty()) {
						debug_mem("Mem Delete: memId %d - write only\n", it->first);
						to_delete.push(it->first);
						continue;
				}
				if(it->second.writtenBy.empty()) {
						debug_mem("Mem Delete: memId %d - read only\n", it->first);
						to_delete.push(it->first);
						continue;
				}

				if(it->second.readLoopId.size() == 1 &&
								it->second.writeLoopId.size() == 1 &&
								*(it->second.readLoopId.begin()) == *(it->second.writeLoopId.begin()))
				{
						debug_mem("!!!Delete low-level dependence: memId %d, readBy(loopid) %d, writted by %d\n", it->first, *(it->second.readLoopId.begin()), *(it->second.writeLoopId.begin()));
						to_delete.push(it->first);
						continue;
				}
				/*
							printf("MemId: %d, (loopId, iterNum[tid]) - X times accessed\n", it->first);
							printf("    ReadBy: ");
							for(map<int,int>::iterator it2 = it->second.readBy.begin(); it2 != it->second.readBy.end(); it2++)
							{
							printf("(%d,%d[%d])-%dtimes ", unitId2LoopId[it2->first], it2->first, unitId2Tid[it2->first], it2->second);  
							}
							printf("\n    WrittenBy: ");
							for(map<int,int>::iterator it2 = it->second.writtenBy.begin(); it2 != it->second.writtenBy.end(); it2++)
							{
							printf("(%d,%d[%d])-%dtimes ", unitId2LoopId[it2->first], it2->first, unitId2Tid[it2->first], it2->second);  
							}
							printf("\n");
							*/
		}

		while(to_delete.size()) {
				memMap.erase(to_delete.top());
				to_delete.pop();
		}


}

void remove_unselected_meminst()
{
		stack<int> to_delete;
		map<int, MemEntry>::iterator mit;

		for(map<int, Entry>::iterator it = log.begin(); it != log.end(); it++)
		{
				if(it->second.type == READ || it->second.type == WRITE)
				{
						mit = memMap.find(it->second.id);
						if(mit == memMap.end()) {
								to_delete.push(it->first);
						}
				}
				if(it->second.type == MALLOC || it->second.type == FREE || it->second.type == REALLOC) to_delete.push(it->first);
		}

		while(to_delete.size()) {
				log.erase(to_delete.top());
				to_delete.pop();
		}
}

void analyze_memory()
{
		prepare_memMap();
		printf("Analyze_memMap\n");
		analyze_memMap();
		printf("====================\n");
		print_memMap();
}

void print_output(char *name)
{
		uint64_t lowAddr, highAddr;
		lowAddr = highAddr = 0;
		lowAddr = LOWADDR;
		highAddr =  HIGHADDR;
		uint64_t offset = 0;
		map<int, Entry>::iterator it;
		map<int, MemEntry>::iterator mit;
		set<int> loopOut;
		set<uint64_t> loopEntryOut;
		set<uint64_t> loopExitOut;
		set<uint64_t> writeOut; // ip - to detect duplicated entries
		set<uint64_t> readOut; // ip

		// output file
		char fname[256];
		sprintf(fname, "%s.out", name);
		FILE *fp = fopen(fname, "w");
		for(it = log.begin(); it != log.end(); it++)
		{
				offset = 0;
				if(it->second.ip >= lowAddr && it->second.ip <= highAddr) offset = it->second.ip-lowAddr;
				if(it->second.type == LOOP_ENTRY) {
						if(loopEntryOut.find(it->second.ip) == loopEntryOut.end()) {
								fprintf(fp, "LE ip %lx (offset %lx) id %d\n", it->second.ip, offset, it->second.id);
								loopEntryOut.insert(it->second.ip);
								loopOut.insert(it->second.id);
						}
				} else if(it->second.type == LOOP_EXIT) {
						if(loopExitOut.find(it->second.ip) == loopExitOut.end()) {
								fprintf(fp, "LX ip %lx (offset %lx) id %d\n", it->second.ip, offset, it->second.id);
								loopExitOut.insert(it->second.ip);
						}
				} else if(it->second.type == WRITE || it->second.type == READ) {
						mit = memMap.find(it->second.id);
						if(mit == memMap.end()) continue;
						if(it->second.type == READ) {
								if(readOut.find(it->second.ip) == readOut.end()) {
										fprintf(fp, "RD ip %lx (offset %lx) id %d\n", it->second.ip, offset, it->second.id);
										readOut.insert(it->second.ip);
								}
						}
						else  {
								if(writeOut.find(it->second.ip) == writeOut.end()) {
										fprintf(fp, "WR ip %lx (offset %lx) id %d\n", it->second.ip, offset, it->second.id);
										writeOut.insert(it->second.ip);
								}
						}
				} else {
						fprintf(stdout, "!!ERROR: unexpected type %d , id %d!\n", it->second.type, it->second.id);
						//exit(0);
				}
		}
		fclose(fp);

		printf("LoopId in the output: ");
		for(set<int>::iterator lit = loopOut.begin(); lit != loopOut.end(); lit++)
		{
				printf("%d ", *lit);
		}
		printf("\n");

		printf("MemId in the output: ");
		for(mit = memMap.begin(); mit != memMap.end(); mit++)
		{
				printf("%d ", mit->first);
		}
		printf("\n");
}

int main(int argc, char** argv)
{
		bool isPreprocessed = false;
		set<int> totalSelectedLoops;

		if(argc < 2) {
				return 0;
		}

		if(read_trace(argv[1]) == false)
		{
				return 0;
		}

		//		print_map(0,1);
		if(strstr(argv[1], "preprocessed") != NULL) isPreprocessed = true;

		if(isPreprocessed == false) {
				fprintf(stdout, "NOT PREPROCESSED file.\n");
				for(int i = 0; i <= maxTid; i++)
				{
						analyze_loop(i);
				}
				remove_unselected_loops();

				for(int i = 0; i <= maxTid; i++) {
						fprintf(stdout, "Tid %d: %ld Loops to instrument!\n", i, selectedLoops[i].size());
						for(map<int, LoopEntry>::iterator it = selectedLoops[i].begin(); it != selectedLoops[i].end(); it++)
						{
								totalSelectedLoops.insert(it->first);
								fprintf(stdout, "Loop id %d: %d iterations, %d/%d syscall called inside the loop. First appeared: %d, Last appeared: %d, total log entries %d\n", it->first, it->second.iter, it->second.syscall, numOfSyscall[i], it->second.firstAppear, it->second.lastAppear, numOfLoopSyscall[i]);
						}
				}

#ifdef ANALYZE_MEM
				if(totalSelectedLoops.size() > 1) {

						//		debug("=================Final map==============\n");
						//		print_map(1);
						preprocess_memory();
						print_preprocessed(argv[1]);
				}
#endif
		} else {
				printf("preprocessed file!\n");
		}

#ifdef ANALYZE_MEM
		if(isPreprocessed || totalSelectedLoops.size() > 1) {
				analyze_memory();
		}
		remove_unselected_meminst();
#endif
		print_output(argv[1]);
}

