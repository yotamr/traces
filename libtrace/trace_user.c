/***
Copyright 2012 Yotam Rubin <yotamrubin@gmail.com>
   Sponsored by infinidat (http://infinidat.com)
   
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
***/

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <pthread.h>

#include "config.h"
#include "macros.h"
#include "trace_lib.h"
#include "trace_user.h"
#include "halt.h"

extern struct trace_log_descriptor __static_log_information_start  __attribute__ ((visibility ("internal")));
extern struct trace_log_descriptor __static_log_information_end __attribute__ ((visibility ("internal")));
extern struct trace_type_definition *__type_information_start __attribute__ ((visibility ("internal")));
struct trace_buffer *current_trace_buffer = NULL;
static unsigned int trace_obj_key;
#ifndef ANDROID
__thread unsigned short trace_current_nesting;
__thread unsigned short tid_cache;
__thread unsigned short pid_cache;
#else
pthread_key_t nesting_key;
static pthread_key_t tid_cache_key;
static pthread_key_t pid_cache_key;
#endif

#ifdef ANDROID
#ifndef	_UNISTD_H
    extern int syscall(int __sysno, ...);
#endif //_UNISTD
#else //ANDROID
#ifndef _SYS_SYSCALL_H_
#ifdef __cplusplus     
    extern long int syscall (long int __sysno, ...) throw ();
#else 
    extern long int syscall(long int __sysno, ...);
#endif //__cplusplus
#endif //_SYS_SYSCALL_H_
#endif //ANDROID



#ifdef ANDROID
unsigned short int trace_get_pid(void)
{
    int *pid = (int *) pthread_getspecific(pid_cache_key);
    if (pid == NULL) {
        pid = (int *) malloc(sizeof(int));
        *pid = syscall(__NR_getpid);
        pthread_setspecific(pid_cache_key, pid);
    }

    return *pid;
}
#else    
unsigned short int trace_get_pid(void)
{
    static __thread int pid_cache = 0;
    if (pid_cache)
		return pid_cache;
    
	pid_cache = syscall(__NR_getpid);
	return pid_cache;
}
#endif    

#ifdef ANDROID    
unsigned short int trace_get_tid(void)
{
    int *tid = (int *) pthread_getspecific(tid_cache_key);
    if (tid == NULL) {
        tid = (int *) malloc(sizeof(int));
        *tid = syscall(__NR_gettid);
        pthread_setspecific(tid_cache_key, tid);
    }

    return *tid;
}
#else    
unsigned short int trace_get_tid(void)
{
    static __thread int tid_cache = 0;
    if (tid_cache)
		return tid_cache;
    
	tid_cache = syscall(__NR_gettid);
	return tid_cache;
}
#endif    
    
unsigned long long trace_get_nsec(void)
{
     struct timespec tv;
     clock_gettime(CLOCK_REALTIME, &tv);
     return ((unsigned long long) tv.tv_sec * 1000000000) + tv.tv_nsec;
}

#ifndef ANDROID    
void trace_increment_nesting_level(void)
{
    trace_current_nesting++;
}
#else
void trace_increment_nesting_level(void)
{
    unsigned short *nesting = (unsigned short *) pthread_getspecific(nesting_key);
    if (nesting == NULL) {
        nesting = (unsigned short *) malloc(sizeof(unsigned short));
        *nesting = 1;
        pthread_setspecific(nesting_key, nesting);
    } else {
        (*nesting)++;
    }
}
#endif    

#ifndef ANDROID    
void trace_decrement_nesting_level(void)
{
    trace_current_nesting--;
}
#else
void trace_decrement_nesting_level(void)
{
    unsigned short *nesting;
    nesting = (unsigned short *) pthread_getspecific(nesting_key);
    (*nesting)--;
}
#endif    

#ifndef ANDROID    
unsigned short trace_get_nesting_level(void)
{
    return trace_current_nesting;
}
#else
unsigned short trace_get_nesting_level(void)
{
    unsigned short *nesting = (unsigned short *) pthread_getspecific(nesting_key);
    if (nesting == NULL) {
        nesting = (unsigned short *) malloc(sizeof(unsigned short));
        *nesting = 0;
        pthread_setspecific(nesting_key, nesting);
        return 5;
    }
    
    return *nesting;
}
#endif    

static void init_records_immutable_data(struct trace_records *records, unsigned long num_records, int severity_type)
{
	while (num_records > 1) {
		records->imutab.max_records_shift++;
		num_records >>= 1;
	}
	num_records = 1 << records->imutab.max_records_shift;
	records->imutab.max_records = num_records;
	records->imutab.max_records_mask = num_records - 1;
    records->imutab.severity_type = severity_type;
}

static void init_records_metadata()
{
    current_trace_buffer->u.records._debug.mutab.current_record = 0;
    current_trace_buffer->u.records._other.mutab.current_record = 0;
    init_records_immutable_data(&current_trace_buffer->u.records._other, TRACE_RECORD_BUFFER_RECS, (1 << TRACE_SEV_FATAL) | (1 << TRACE_SEV_ERROR) | (1 << TRACE_SEV_INFO) | (1 << TRACE_SEV_WARN));
    init_records_immutable_data(&current_trace_buffer->u.records._debug, TRACE_RECORD_BUFFER_RECS, (1 << TRACE_SEV_DEBUG));
    init_records_immutable_data(&current_trace_buffer->u.records._funcs, TRACE_RECORD_BUFFER_RECS, (1 << TRACE_SEV_FUNC_TRACE));
}

struct trace_record *trace_get_record(enum trace_severity severity, unsigned int *generation)
{
	struct trace_records *records;
	struct trace_record *record;
	unsigned int record_index;

    if (severity == TRACE_SEV_FUNC_TRACE) {
        records = &current_trace_buffer->u.records._funcs;
    } else if (severity == TRACE_SEV_DEBUG) {
		records = &current_trace_buffer->u.records._debug;
    } else {
		records = &current_trace_buffer->u.records._other;
    }

    record_index = __sync_fetch_and_add(&records->mutab.current_record, 1);
    *generation = record_index >> records->imutab.max_records_shift;
    record_index &= records->imutab.max_records_mask;

	record = &records->records[record_index % TRACE_RECORD_BUFFER_RECS];
	return record;
}

unsigned int trace_allocate_obj_key(void)
{
    if (trace_obj_key >= TRACE_MAX_OBJS_PER_PROCESS) {
        abort();
    }

    printf("Trace: %d\n", trace_obj_key);
    unsigned int new_obj_key = trace_obj_key;
    trace_obj_key++;
    return new_obj_key;
}

static void map_dynamic_log_buffers(void)
{
    char shm_name[0x100];
    snprintf(shm_name, sizeof(shm_name), "%s%s%d_dynamic_trace_data", SHM_PATH, TRACE_SHM_ID, getpid());
    int shm_fd = open(shm_name, O_CREAT | O_RDWR, 0660);
    if (shm_fd < 0) {
        return;
    }
    ASSERT(shm_fd >= 0);
    int rc = ftruncate(shm_fd, sizeof(struct trace_buffer));
    ASSERT (0 == rc);
    void *mapped_addr = mmap(NULL, sizeof(struct trace_buffer), PROT_WRITE, MAP_SHARED, shm_fd, 0);
    memset(mapped_addr, 0, sizeof(struct trace_buffer));
    ASSERT(mapped_addr != NULL);
    current_trace_buffer = (struct trace_buffer *)mapped_addr;
    init_records_metadata();
}

static int TRACE__register_buffer(void)
{
    if (!current_trace_buffer) {
        map_dynamic_log_buffers();
    }
    
    return 0;
}

static void TRACE__init(void) __attribute__((constructor));
static void TRACE__init(void)
{
    TRACE__register_buffer();
    #ifdef ANDROID
    pthread_key_create(&nesting_key, NULL);
    pthread_key_create(&tid_cache_key, NULL);
    pthread_key_create(&pid_cache_key, NULL);
    #endif
}


static int delete_shm_files(unsigned short pid)
{
    char dynamic_trace_filename[0x100];
    char static_log_data_filename[0x100];
    char full_dynamic_trace_filename[0x100];
    char full_static_log_data_filename[0x100];
    int rc;
    snprintf(dynamic_trace_filename, sizeof(dynamic_trace_filename), "_trace_shm_%d_dynamic_trace_data", pid);
    snprintf(static_log_data_filename, sizeof(static_log_data_filename), "_trace_shm_%d_static_trace_metadata", pid);
    snprintf(full_dynamic_trace_filename, sizeof(full_dynamic_trace_filename), "%s/%s", SHM_PATH, dynamic_trace_filename);
    snprintf(full_static_log_data_filename, sizeof(full_static_log_data_filename), "%s/%s", SHM_PATH, static_log_data_filename);

    rc = unlink(full_dynamic_trace_filename);
    rc |= unlink(full_static_log_data_filename);

    return rc;
}

struct trace_buffer *get_current_trace_buffer(void) {
    return current_trace_buffer;
}

void TRACE__fini(void)
{
    current_trace_buffer = NULL;
    delete_shm_files(getpid());
}
