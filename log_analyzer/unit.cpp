#include <stdio.h>
#include "auditlog.h"


typedef struct {
		map<INT, INT> lastWrite;
		map<INT, INT> lastSrcLoc;
} MemWrite;

map<INT, INT> highBit;
map<INT, INT> srcLoc;
map<INT, MemWrite> memWrite; 
map<INT, INT> unitMax;
map<INT, set<INT> > unitMap;
map<long int, INT> unitMapFinder;
INT unitMapNum = 0;

void print_dep_units()
{
#ifdef NDEBUG
		return;
#endif
		map<INT, set<INT> >::iterator iter;
		int num = 0;

		for(iter = unitMap.begin(); iter != unitMap.end(); iter++)
		{
				fprintf(stderr, "UnitMap %ld : ", iter->first);
				set<INT>::iterator iter2;
				for(iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++)
				{
						INT pid = (*iter2) >> 32;
						INT unitid = ((*iter2) << 32) >> 32;
						if(num++ > 5) { 
								fprintf(stderr, "\n");
								num = 0;
						}
						fprintf(stderr, "%ld,%ld - ",pid, unitid);
				} 
				fprintf(stderr, "\n");
		}
}

INT get_dep_units(INT pid, INT unitid)
{
		INT id = pid;
		id = id << 32;
		id+=unitid;

		map<long int, INT>::iterator iter;

		iter = unitMapFinder.find(id);
		if(iter == unitMapFinder.end()) return -1;

		return iter->second;
}

void insert_unitMap(INT from, INT to)
{
		if(from == to) return;
		map<INT, set<INT> >::iterator iter;

		map<long int, INT>::iterator miter, miter2;
		miter = unitMapFinder.find(from);
		miter2 = unitMapFinder.find(to);

		if(miter != unitMapFinder.end() && miter2 != unitMapFinder.end())
		{
				return ;
		} else if(miter == unitMapFinder.end() && miter2 == unitMapFinder.end()) {
				set<INT> s;
				s.insert(from);
				s.insert(to);
				unitMap.insert(pair<INT, set<INT> >(unitMapNum,s));
				unitMapFinder.insert(pair<long int, INT> (from, unitMapNum));
				unitMapFinder.insert(pair<long int, INT> (to, unitMapNum));
				unitMapNum++;
		} else if(miter == unitMapFinder.end()) {
				unitMap[miter2->second].insert(from);
				unitMapFinder.insert(pair<long int, INT>(from, miter2->second));
		} else {
				unitMap[miter->second].insert(to);
				unitMapFinder.insert(pair<long int, INT>(to, miter->second));
		}
}


void unit_insert_read(INT spid, INT pid, INT unitid, unsigned INT addr)
{
		map<INT, MemWrite>::iterator iter;

		iter = memWrite.find(spid);

		INT from = pid;
		from = from << 32;
		from+=unitid;

		INT p, u;
		p = from >> 32;
		u = (from << 32) >> 32;
//		debug("Unit insert read : spid %ld, pid %ld, unitid %ld, addr %lx, t %ld (pid %ld, uid %ld)\n", spid, pid, unitid, addr, from, p, u);
		
		if(iter == memWrite.end()) return;

		map<INT, INT>::iterator iter2, iter3;
		iter2 = iter->second.lastWrite.find(addr);
		iter3 = iter->second.lastSrcLoc.find(addr);

		if(iter2 == iter->second.lastWrite.end()) return;

		INT to = iter2->second;
		p = to >> 32;
		u = (to << 32) >> 32;
		if(from != to) debug("Unit dependence detected (addr %lx) : last write src %ld (pid %ld, uid %ld) - src %ld (pid %ld, uid %ld)\n", addr, iter3->second, p, u, srcLoc[pid], pid, unitid );
		insert_unitMap(from, to);
		//print_dep_units();
}

void unit_insert_write(INT spid, INT pid, INT unitid, unsigned INT addr)
{
		map<INT, MemWrite>::iterator iter;

		iter = memWrite.find(spid);

		INT t = pid;
		t = t << 32;
		t+=unitid;

		INT p, u;
		p = t >> 32;
		u = (t << 32) >> 32;
//		debug("Unit insert write : spid %ld, pid %ld, unitid %ld, addr %lx, t %ld (pid %ld, uid %ld)\n", spid, pid, unitid, addr, t, p, u);
		if(iter == memWrite.end())
		{
				MemWrite mw;
				mw.lastWrite.insert(pair<INT, INT>(addr, t));
				mw.lastSrcLoc.insert(pair<INT, INT>(addr, srcLoc[pid]));
				memWrite.insert(pair<INT, MemWrite>(spid, mw));
		} else {
				map<INT, INT>::iterator iter2, iter3;
				iter2 = iter->second.lastWrite.find(addr);
				iter3 = iter->second.lastSrcLoc.find(addr);
				if(iter2 == iter->second.lastWrite.end())
				{
						iter->second.lastWrite.insert(pair<INT, INT>(addr, t));
						iter->second.lastSrcLoc.insert(pair<INT, INT>(addr, srcLoc[pid]));
				} else {
						iter2->second = t;
						iter3->second = srcLoc[pid];
				}
		}
}

map<INT, map<unsigned INT, INT> > kyu_test_access[2];
map<INT, INT> kyu_test_src[2];

void kyu_count_mem_access(int write, INT spid, INT pid, INT unitid, unsigned INT addr, INT src)
{
		static int largest_tid = 0;
		if(pid - spid > largest_tid) {
				largest_tid = pid - spid;
				printf("largest_tid = %ld\n", largest_tid);
		}
		if(write) kyu_test_src[1][src]++;
		else kyu_test_src[0][src]++;

		map<INT, map<unsigned INT, INT> >::iterator iter;
		map<unsigned INT, INT>::iterator iter2;

		iter = kyu_test_access[write].find(unitid);
		if(iter == kyu_test_access[write].end()) {
				map<unsigned INT, INT> t;
				t.insert(pair<unsigned INT, INT> (addr, 1));
				kyu_test_access[write].insert(pair<INT, map<unsigned INT, INT> > (unitid, t));
		} else {
				iter2 = iter->second.find(addr);
				if(iter2 == iter->second.end()) {
						iter->second.insert(pair<unsigned INT, INT> (addr, 1));
				} else {
						iter2->second++;
				}
		}
}

void kyu_print_mem_access()
{
		int single_access[2];
		int two_digit_access[2];
		int over_th_access[2];
		single_access[0] = single_access[1] = two_digit_access[0] = two_digit_access[1] = over_th_access[0] = over_th_access[1] = 0;
		int write = 0;
		INT num_save[2], num_total[2];
		num_save[0] = num_save[1] = num_total[0] = num_total[1] = 0;

		map<INT, map<unsigned INT, INT> >::iterator iter;
		map<unsigned INT, INT>::iterator iter2;
		for(write = 0; write < 2; write++) {
				if(write == 0) 
						printf("MEM_READ COUNT:\n");
				else
						printf("\n\nMEM_WRITE COUNT:\n");

				for(iter = kyu_test_access[write].begin(); iter != kyu_test_access[write].end(); iter++)
				{
						int total_access = 0;
						for(iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++)
						{
								if(iter2->second <= 10) single_access[write]++;
								else if(iter2->second <= 100) two_digit_access[write]++;
								else over_th_access[write]++;
								num_save[write] += iter2->second - 1;
								num_total[write] += iter2->second;
								total_access += iter2->second;
								//else {
								//		printf("unit %ld, addr %ld : %ld times\n", iter->first, iter2->first, iter2->second);
								//}
						}
						printf("unit %ld accesses %ld different addresses (total %d accesses)\n", iter->first, iter->second.size(), total_access);
				}
				if(write == 0) {
						printf("MEM_READ < 10 COUNT/addr: %d\n", single_access[0]);
						printf("MEM_READ 10 ~ 100 COUNT/addr: %d\n", two_digit_access[0]);
						printf("MEM_READ > 1000 COUNT/addr: %d\n", over_th_access[0]);
						printf("READ # of potential reduction: %ld (out of %ld) \n", num_save[0], num_total[0]);
				} else {
						printf("MEM_WRITE < 10 COUNT/addr: %d\n", single_access[1]);
						printf("MEM_WRITE 10 ~ 100 COUNT/addr: %d\n", two_digit_access[1]);
						printf("MEM_WRITE > 1000 COUNT/addr: %d\n", over_th_access[1]);
						printf("WRITE # of potential reduction: %ld (out of %ld) \n", num_save[1], num_total[1]);
				}
		}
		printf("# of potential reduction: %ld (out of %ld) : %lf\% \n", (num_save[0] + num_save[1]), (num_total[0] + num_total[1]), (float) (((num_save[0]+num_save[1]) * 100) / (num_total[0] + num_total[1])));

		map<INT, INT>::iterator iter3;
		for(write = 0; write < 2; write++) {
				if(write == 0) 
						printf("MEM_READ SRC:\n");
				else
						printf("\n\nMEM_WRITE SRC:\n");

				for(iter3 = kyu_test_src[write].begin(); iter3 != kyu_test_src[write].end(); iter3++)
				{
						printf("\t\tSRC %ld - %ld times, %lf\%\n", iter3->first, iter3->second, (float)(iter3->second*100)/num_total[write]);
				}
		}
}

int KYU_ignore_src = 0;
bool ignore_src(INT src)
{
		//if(src != 19 && src != 3 && src != 14) return true;
		//if(src < KYU_ignore_src && src != 3 && src != 14) return true;
		//if(src < 40 && src != 3 && src != 14) return true;
		if(src !=52 && src != 53 &&	src != 3 && src != 14) return true;
		//if( src != 52 &&	src != 53 && src != 3) return true;
		return false;
}

void unit_detect_mem(INT spid, INT pid, INT unitid)
{
		unsigned INT addr;

		if(logentry.arg[0] == 0xffffff36) {
				srcLoc[logentry.pid] = logentry.arg[1];
		} else if(logentry.arg[0] == 0xffffff38) { //-200 read high32bit
				highBit[logentry.pid] = logentry.arg[1];
		} else if(logentry.arg[0] == 0xffffff37) { // -201 read low32bit
#ifdef IGNORE_SRC
				if(ignore_src(srcLoc[logentry.pid])) return;
				//if(srcLoc[logentry.pid] == IGNORE_SRC || srcLoc[logentry.pid] == 26 || srcLoc[logentry.pid] == 3) return;
#endif
				addr = highBit[logentry.pid];
				addr = addr << 32;
				addr += logentry.arg[1];
				highBit[logentry.pid] = 0;
				debug("log %ld, src %ld [%ld,%ld spid %ld] unit read memory %lx\n",logentry.log_num, srcLoc[logentry.pid], logentry.pid, unitid, spid, addr);
#ifdef KYU_TEST
				kyu_count_mem_access(0, spid, pid, unitid, addr, srcLoc[logentry.pid]);
				srcLoc[logentry.pid] = 0;
				return;
#endif
				unit_insert_read(spid, pid, unitid, addr);
				srcLoc[logentry.pid] = 0;

		} else if(logentry.arg[0] == 0xfffffed2) {
				srcLoc[logentry.pid] = logentry.arg[1];
		} else if(logentry.arg[0] == 0xfffffed4) { // || logentry.arg[0] == 0xfffffe70) { // -300 write high32bit
				highBit[logentry.pid] = logentry.arg[1];
		} else if(logentry.arg[0] == 0xfffffed3) {// || logentry.arg[0] == 0xfffffe6f) { // -301 write low32bit
#ifdef IGNORE_SRC
				if(ignore_src(srcLoc[logentry.pid])) return;
#endif
				addr = highBit[logentry.pid];
				addr = addr << 32;
				addr += logentry.arg[1];
				highBit[logentry.pid] = 0;
				debug("log %ld, src %ld [%ld,%ld spid %ld] unit write memory %lx\n",logentry.log_num, srcLoc[logentry.pid], logentry.pid, unitid, spid, addr);
				//unit_detect_dep(logentry.pid, logentry.unitid, addr);
#ifdef KYU_TEST
				kyu_count_mem_access(1, spid, pid, unitid, addr, srcLoc[logentry.pid]);
				srcLoc[logentry.pid] = 0;
				return;
#endif
				unit_insert_write(spid, pid, unitid, addr);
				srcLoc[logentry.pid] = 0;
		}
}

bool is_unit_end()
{
		if(logentry.sysnum == SYS_kill && logentry.arg[0] == 0xffffff9b) { //kill(-101,xx);
				map<INT,INT>::iterator ui;
				ui = unitId.find(logentry.pid);
				if(ui == unitId.end())
				{
					 debug("[%ld,%ld] UNIT END!\n", logentry.pid, 1);
						unitId.insert(pair<INT,INT>(logentry.pid, 1));
				} else {
						ui->second = ui->second+1;
						//printf("UNIT END! - %ld-%ld\n", logentry.pid, ui->second);
				}

				//logentry.unitid++;

				return true;
		}

		return false;
	//	if(logentry.sysnum == SYS_clone || logentry.sysnum == SYS_fork)
	//			return true;

}

int KYU_test_unit;
bool test_unit(INT num)
{
		//if(num == 10) return false;
		//if(num >= 10 && num != KYU_test_unit) return false;
//		if(num > 10) printf("loop %d\n", num);
		return true;
}

bool is_unit_begin_backward()
{
		//if(logentry.sysnum == SYS_kill && logentry.arg[0] == 0xffffff9c  && logentry.arg[1] < 10) { //kill(-100,xx);
		if(logentry.sysnum == SYS_kill && logentry.arg[0] == 0xffffff9c) { //kill(-100,xx);
				if(!test_unit(logentry.arg[1])) return false;
				debug("[%ld,%ld] UNIT BEGIN BACKWARD! (%ld)\n", logentry.pid, logentry.unitid, logentry.log_num);
				map<INT,INT>::iterator ui;
				ui = unitId.find(logentry.pid);
				if(ui == unitId.end())
						unitId.insert(pair<INT,INT>(logentry.pid, unitMax[logentry.pid]));
				else ui->second = ui->second-1;

				return true;
		}
		if(logentry.sysnum == SYS_clone || logentry.sysnum == SYS_fork)
				return true;

		return false;
}

void unit_id_reset()
{
		unitId.clear();
		unitMax.clear();
}

bool is_unit_begin_forward()
{
		//if(logentry.sysnum == SYS_kill && logentry.arg[0] == 0xffffff9c  && logentry.arg[1] < 10) { //kill(-100,xx);
		if(logentry.sysnum == SYS_kill && logentry.arg[0] == 0xffffff9c) { //kill(-100,xx);
				if(!test_unit(logentry.arg[1])) return false;
				map<INT,INT>::iterator ui;
				ui = unitId.find(logentry.pid);
				if(ui == unitId.end()) {
						unitId.insert(pair<INT,INT>(logentry.pid, 1));
						debug("Unit begin, %ld-%ld, lognum %ld\n", logentry.pid, 1, logentry.log_num);
						logentry.unitid = 1;
				} else {
						ui->second = ui->second+1;
						unitMax[logentry.pid] = ui->second;
						logentry.unitid = ui->second;
						debug("Unit begin, %ld-%ld, lognum %ld\n", logentry.pid, ui->second, logentry.log_num);
				}

				return true;
		}
		if(logentry.sysnum == SYS_clone || logentry.sysnum == SYS_fork)
				return true;

		return false;
}
