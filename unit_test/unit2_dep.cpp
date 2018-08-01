#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "UBSI_dep.h"
#include <stdint.h>
#include <unistd.h>

#define MAX 50
pthread_mutex_t the_mutex;
pthread_cond_t condc;

char *buffer[MAX];

void* producer(void *ptr) {
  int i, n, fd;
		char fname[64], temp[16];

  for (i = 0; i < MAX; i++) {
				UBSI_LOOP_ENTRY(1);
				bzero(temp, 16);
				sprintf(fname, "input/data%02d.txt",i);
				fd = open(fname, O_RDONLY);
				if(fd < 0) {
						printf("file open fails: %s\n", fname);
						continue;
				}

				buffer[i] = (char*) malloc(16);
				n = read(fd, temp, 16);

    pthread_mutex_lock(&the_mutex);
				UBSI_MEM_WRITE(buffer[i]);
				memcpy(buffer[i], temp, 16);
    pthread_cond_signal(&condc);
    pthread_mutex_unlock(&the_mutex);
				close(fd);
  }

		UBSI_LOOP_EXIT(1);
  pthread_exit(0);
}

void* consumer(void *ptr) {
  int i, n, fd;
		char temp[16], fname[64];

  for (i = 0; i < MAX; i++) {
				UBSI_LOOP_ENTRY(2);
    pthread_mutex_lock(&the_mutex);	
    while (buffer[i] == NULL)		
      pthread_cond_wait(&condc, &the_mutex);
    pthread_mutex_unlock(&the_mutex);
				
				usleep(1);
				UBSI_MEM_READ(buffer[i]);
				memcpy(temp, buffer[i], 16);
				sprintf(fname, "output/output%02d.txt", i);

				fd = open(fname, O_RDWR|O_CREAT, 0644);
				if(fd < 0) {
						printf("file open fails: %s\n", fname);
						continue;
				}
				n = write(fd, temp, strlen(temp));
				close(fd);
  }
		UBSI_LOOP_EXIT(2);
  pthread_exit(0);
}

int main(int argc, char **argv) {
  pthread_t pro, con;
		int i;
		for(i = 0; i < MAX; i++)
		{
			 buffer[i] = NULL;
		}

  pthread_mutex_init(&the_mutex, NULL);	
  pthread_cond_init(&condc, NULL);

  pthread_create(&con, NULL, consumer, NULL);
  pthread_create(&pro, NULL, producer, NULL);

  pthread_join(pro, NULL);
  pthread_join(con, NULL);

  pthread_mutex_destroy(&the_mutex);
  pthread_cond_destroy(&condc);

}

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

