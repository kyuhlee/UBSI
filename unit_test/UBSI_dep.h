#ifndef UBSI_DEFINE
#define UBSI_DEFINE
#include <stdint.h>
#include <signal.h>
#include <sys/types.h>
#include "uthash.h"

typedef struct UBSI_cache_t {
		intptr_t addr;
		int unit;
		UT_hash_handle hh;
} UBSI_cache_t;

typedef struct UBSI_dep_cache_t {
		int dep;
		UT_hash_handle hh;
} UBSI_dep_cache_t;

// extern variables are declared in js/src/builtin/TypedObject.cpp
extern __thread int UBSI_uid;
extern int UBSI_global_uid;
extern pthread_rwlock_t UBSI_cache_lock;
extern pthread_mutex_t UBSI_uid_lock;
extern UBSI_cache_t *UBSI_cache;
extern __thread UBSI_dep_cache_t *UBSI_dep_cache;

int UBSI_check_dep_cache(int dep);

#define UBSI_clear_dep_cache() { \
		UBSI_dep_cache_t *UBSI_dep_cur, *UBSI_dep_tmp; \
		HASH_ITER(hh, UBSI_dep_cache, UBSI_dep_cur, UBSI_dep_tmp) { \
				HASH_DEL(UBSI_dep_cache, UBSI_dep_cur); \
				free(UBSI_dep_cur); \
		} \
		UBSI_dep_cache = NULL;\
}

#define UBSI_MEM_WRITE(UBSI_addr) { \
		if(UBSI_uid > 0) { \
				intptr_t value = (intptr_t)UBSI_addr; \
				UBSI_cache_t *UBSI_tmp, *UBSI_tmp2; \
				pthread_rwlock_rdlock(&UBSI_cache_lock);\
				HASH_FIND(hh, UBSI_cache, &value, sizeof(intptr_t), UBSI_tmp); \
				pthread_rwlock_unlock(&UBSI_cache_lock);\
				if(UBSI_tmp) { \
						UBSI_tmp->unit = UBSI_uid;\
				} else { \
						UBSI_tmp = new UBSI_cache_t(); \
						UBSI_tmp->addr = value; \
						UBSI_tmp->unit = UBSI_uid; \
						pthread_rwlock_wrlock(&UBSI_cache_lock); \
						HASH_ADD(hh, UBSI_cache, addr, sizeof(intptr_t), UBSI_tmp); \
						pthread_rwlock_unlock(&UBSI_cache_lock); \
				} \
		}\
}

#define UBSI_MEM_READ(addr) { \
		if(UBSI_uid > 0) { \
				intptr_t value = (intptr_t)addr; \
				UBSI_cache_t *UBSI_tmp3; \
				int last_written_unit = 0; \
				pthread_rwlock_rdlock(&UBSI_cache_lock); \
				HASH_FIND(hh, UBSI_cache, &value, sizeof(intptr_t), UBSI_tmp3); \
				pthread_rwlock_unlock(&UBSI_cache_lock); \
				if(UBSI_tmp3) last_written_unit = UBSI_tmp3->unit; \
				if(last_written_unit > 0 && last_written_unit != UBSI_uid) {\
						if(UBSI_check_dep_cache(last_written_unit) == 0) { \
								kill(-400, last_written_unit); \
						}\
				}\
		}\
}

#define UBSI_LOOP_ENTRY(loopId) { \
		pthread_mutex_lock(&UBSI_uid_lock); \
  int UBSI_local_tmp = ++UBSI_global_uid; \
		pthread_mutex_unlock(&UBSI_uid_lock); \
		UBSI_uid = UBSI_local_tmp; \
  kill(-100, loopId); \
  kill(-102, UBSI_uid); \
	 UBSI_clear_dep_cache();\
}

#define UBSI_LOOP_EXIT(loopId) { \
		UBSI_uid = 0; \
  kill(-101, loopId); \
}

#endif

/*
__thread int UBSI_uid = 0;
pthread_rwlock_t UBSI_cache_lock = PTHREAD_RWLOCK_INITIALIZER;
pthread_mutex_t UBSI_uid_lock = PTHREAD_MUTEX_INITIALIZER;
int UBSI_global_uid = 0;
UBSI_cache_t *UBSI_cache;
__thread UBSI_dep_cache_t *UBSI_dep_cache;

int UBSI_check_dep_cache(int dep)
{
		UBSI_dep_cache_t *tmp;
		HASH_FIND(hh, UBSI_dep_cache, &dep, sizeof(int), tmp);
		if(tmp) return tmp->dep;
		
		tmp = new UBSI_dep_cache_t();
		tmp->dep = dep;

		HASH_ADD(hh, UBSI_dep_cache, dep, sizeof(int), tmp);
		return 0;
}

void UBSI_update_cache(intptr_t addr)
{
		UBSI_cache_t *tmp, *cur, *tmp2;
		pthread_rwlock_rdlock(&UBSI_cache_lock);
		HASH_FIND(hh, UBSI_cache, &addr, sizeof(intptr_t), tmp);
		pthread_rwlock_unlock(&UBSI_cache_lock);

		if(tmp) {
				tmp->unit = UBSI_uid;
				return;
		}

		tmp = new UBSI_cache_t();
		tmp->addr = addr;
		tmp->unit = UBSI_uid;
		pthread_rwlock_wrlock(&UBSI_cache_lock);
		HASH_ADD(hh, UBSI_cache, addr, sizeof(intptr_t), tmp);
		pthread_rwlock_unlock(&UBSI_cache_lock);
}
*/

