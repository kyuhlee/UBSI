#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "uthash.h"
#include "process_dep.h"

#define false 0
#define true 1

int next_clusterid = 1;
struct unit_t *unit_table = NULL;
struct unit_clusterid_t *clusterid_table = NULL;

void print_unit(thread_unit_t *unit, FILE *fp)
{
			fprintf(fp, "(pid=%d thread_time=%d.%d unitid=%d iteration=%d time=%.3lf count=%d) ",
		  unit->tid, unit->thread_time.seconds, unit->thread_time.milliseconds, 
				unit->loopid, unit->iteration, unit->timestamp, unit->count);
}

void print_unit_table(FILE *fp, const char *table)
{
		unit_t *ut, *tmp;
		int id;
		unit_clusterid_t *ct, *ctmp;
		HASH_ITER(hh, unit_table, ut, tmp) {
				HASH_FIND(hh, clusterid_table, &(ut->clusterid), sizeof(int), ct);
				if(ct == NULL)	id = ut->clusterid;
				else id = ct->newid;
				fprintf(fp, "INSERT INTO %s (unitid, tid, thread_time, loopid, iteration, timestamp, count) VALUES (%d, %d, %d.%d, %d, %d, %.3lf, %d);\n", table, id, ut->unit.tid, ut->unit.thread_time.seconds, ut->unit.thread_time.milliseconds, ut->unit.loopid, ut->unit.iteration, ut->unit.timestamp, ut->unit.count);
		}
}

int get_unitid(thread_unit_t *unit)
{
		struct unit_t *u;
		unit_clusterid_t *ctmp;

		HASH_FIND(hh, unit_table, unit, sizeof(thread_unit_t), u);
		if(u == NULL) {
				unit_t *new_u = (unit_t*) malloc(sizeof(unit_t));
				new_u->clusterid = next_clusterid;
				memcpy((void*)&new_u->unit, (void*)unit, sizeof(thread_unit_t));
				HASH_ADD(hh, unit_table, unit, sizeof(thread_unit_t), new_u);
				next_clusterid++;
				return next_clusterid-1;
		}
		HASH_FIND(hh, clusterid_table, &(u->clusterid), sizeof(int), ctmp);
		if(ctmp == NULL) return u->clusterid;
		else return ctmp->newid;
}

int unit_dep(thread_unit_t *unit, thread_unit_t *dep)
{
		struct unit_t *u, *d;
		HASH_FIND(hh, unit_table, unit, sizeof(thread_unit_t), u);
		HASH_FIND(hh, unit_table, dep, sizeof(thread_unit_t), d);

		if(u == NULL && d == NULL) {
				unit_t *new_u = (unit_t*) malloc(sizeof(unit_t));
				new_u->clusterid = next_clusterid;
				memcpy((void*)&new_u->unit, (void*)unit, sizeof(thread_unit_t));
				HASH_ADD(hh, unit_table, unit, sizeof(thread_unit_t), new_u);

				unit_t *new_d = (unit_t*) malloc(sizeof(unit_t));
				new_d->clusterid = next_clusterid;
				memcpy((void*)&new_d->unit, (void*)dep, sizeof(thread_unit_t));
				HASH_ADD(hh, unit_table, unit, sizeof(thread_unit_t), new_d);

				next_clusterid++;
		} else if(u == NULL) {
				// put unit into dep cluster
				unit_t *new_u = (unit_t*) malloc(sizeof(unit_t));
				new_u->clusterid = d->clusterid;
				memcpy((void*)&new_u->unit, (void*)unit, sizeof(thread_unit_t));
				HASH_ADD(hh, unit_table, unit, sizeof(thread_unit_t), new_u);
		} else if(d == NULL) {
				// put dep into unit cluster
				unit_t *new_d = (unit_t*) malloc(sizeof(unit_t));
				new_d->clusterid = u->clusterid;
				memcpy((void*)&new_d->unit, (void*)dep, sizeof(thread_unit_t));
				HASH_ADD(hh, unit_table, unit, sizeof(thread_unit_t), new_d);
		} else {
				if(u->clusterid != d->clusterid) {
						//instead of merging them, we use another table.
						unit_clusterid_t *ct, *ctmp;
						ct = (unit_clusterid_t*)malloc(sizeof(unit_clusterid_t));
						ct->clusterid = d->clusterid;
						ct->newid = u->clusterid;
						HASH_FIND(hh, clusterid_table, &(u->clusterid), sizeof(int), ctmp);
						if(ctmp != NULL) ct->newid = ctmp->newid;
						HASH_ADD(hh, clusterid_table, clusterid, sizeof(int), ct);
				} else {
						//nothing to do.
				}
		}
}

int scan_unit(char *ptr, thread_unit_t *unit)
{
		sscanf(ptr, "(pid=%d thread_time=%d.%d unitid=%d iteration=%d time=%lf count=%d)", 
		  &(unit->tid), &(unit->thread_time.seconds), &(unit->thread_time.milliseconds), 
				&(unit->loopid), &(unit->iteration), &(unit->timestamp), &(unit->count));
}
void file_scan(FILE *fp)
{
		char *ptr;
		char buf[1048576];
		thread_unit_t unit, dep;

		fgets(buf, 1048576, fp);
		while(!feof(fp)) 
		{
				ptr = strstr(buf, " unit=(");
				assert(ptr);
				scan_unit(ptr+6, &unit);

				ptr = strstr(buf, " dep=(");
				assert(ptr);
				scan_unit(ptr+5, &dep);
				
				unit_dep(&unit, &dep);

				fgets(buf, 1048576, fp);
		}
}

int scan_dep_file(const char *log_name)
{
		FILE *fp;

		if((fp = fopen(log_name, "r")) == NULL) {
				return -1;
		}

		file_scan(fp);

		fclose(fp);
}
