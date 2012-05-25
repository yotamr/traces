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

#ifndef __TRACE_LIB_H__
#define __TRACE_LIB_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"
#include "trace_defs.h"
#include <sys/syscall.h>
#include <time.h>    
#include <pthread.h>
#ifdef __repr__
#undef __repr__
#endif
    
#define __repr__ _trace_represent(unsigned int *buf_left, struct trace_record *_record, struct trace_record **__record_ptr, unsigned char **typed_buf)
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

#define _O_RDONLY	00000000   
extern struct trace_buffer *current_trace_buffer;
extern struct trace_log_descriptor __static_log_information_start;
extern struct trace_log_descriptor __static_log_information_end;
extern struct trace_type_definition *__type_information_start;

#ifndef ANDROID    
extern __thread unsigned short trace_current_nesting;
#else
extern pthread_key_t nesting_key;
extern pthread_key_t pid_cache_key;
extern pthread_key_t tid_cache_key;
#endif    
#ifdef ANDROID    
static inline unsigned short int trace_get_pid(void)
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
static inline unsigned short int trace_get_pid(void)
{
    static __thread int pid_cache = 0;
    if (pid_cache)
		return pid_cache;
    
	pid_cache = syscall(__NR_getpid);
	return pid_cache;
}
#endif    

#ifdef ANDROID    
static inline unsigned short int trace_get_tid(void)
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
static inline unsigned short int trace_get_tid(void)
{
    static __thread int tid_cache = 0;
    if (tid_cache)
		return tid_cache;
    
	tid_cache = syscall(__NR_gettid);
	return tid_cache;
}
#endif    
    
static inline unsigned long long trace_get_nsec(void)
{
     struct timespec tv;
     clock_gettime(CLOCK_REALTIME, &tv);
     return ((unsigned long long) tv.tv_sec * 1000000000) + tv.tv_nsec;
}

#ifndef ANDROID    
static inline void trace_increment_nesting_level(void)
{
    trace_current_nesting++;
}
#else
static inline void trace_increment_nesting_level(void)
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
static inline void trace_decrement_nesting_level(void)
{
    trace_current_nesting--;
}
#else
static inline void trace_decrement_nesting_level(void)
{
    unsigned short *nesting;
    nesting = (unsigned short *) pthread_getspecific(nesting_key);
    (*nesting)--;
}
#endif    

#ifndef ANDROID    
static inline unsigned short trace_get_nesting_level(void)
{
    return trace_current_nesting;
}
#else
static inline unsigned short trace_get_nesting_level(void)
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
    
    
#define trace_atomic_t int

static inline int trace_strnlen(const char *c, int l)
{
	int r = 0;

	while (*c  &&  l >= 0) {
		r++;
		c++;
		l--;
	}

	return r;
}

struct trace_records_mutable_metadata {
	trace_atomic_t current_record;
	trace_atomic_t reserved[14];

	unsigned long long latest_flushed_ts;
};

struct trace_records_immutable_metadata {
	unsigned int max_records;
	unsigned int max_records_mask;
	unsigned int max_records_shift;
	unsigned int severity_type;
};

struct trace_records {
	struct trace_records_immutable_metadata imutab;
	struct trace_records_mutable_metadata mutab;
	struct trace_record records[TRACE_RECORD_BUFFER_RECS];
};


struct trace_buffer {
    unsigned int pid;
    union {
        struct trace_records _all_records[TRACE_BUFFER_NUM_RECORDS];
        struct {
            struct trace_records _funcs;
            struct trace_records _debug;
            struct trace_records _other;
        } records;
    } u;
};

static inline void set_current_trace_buffer_ptr(struct trace_buffer *trace_buffer_ptr)
{
    current_trace_buffer = trace_buffer_ptr;
}

static inline struct trace_record *trace_get_record(enum trace_severity severity, unsigned int *generation)
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
#ifdef __cplusplus
}
#endif
#endif
