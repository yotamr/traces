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

#define TRACE_SHM_ID "_trace_shm_"    
#include "trace_defs.h"
#include <sys/syscall.h>
#include <time.h>    

#ifdef __repr__
#undef __repr__
#endif
    
#define __repr__ _trace_represent(unsigned int *buf_left, struct trace_record *_record, struct trace_record **__record_ptr, unsigned char **typed_buf)
#ifndef	_UNISTD_H    
#ifdef __cplusplus     
    extern long int syscall (long int __sysno, ...) throw ();
#else
    extern long int syscall(long int __sysno, ...);
#endif
#endif    

#define _O_RDONLY	00000000   
extern struct trace_buffer *current_trace_buffer;
extern struct trace_log_descriptor __static_log_information_start;
extern struct trace_log_descriptor __static_log_information_end;
extern struct trace_type_definition *__type_information_start;
extern __thread unsigned short trace_current_nesting; 
    
static inline unsigned short int trace_get_pid(void)
{
    static __thread int pid_cache = 0;
    if (pid_cache)
		return pid_cache;
	pid_cache = syscall(__NR_getpid);
	return pid_cache;
}
    
static inline unsigned short int trace_get_tid(void)
{
    static __thread int tid_cache = 0;
    if (tid_cache)
		return tid_cache;
	tid_cache = syscall(__NR_gettid);
	return tid_cache;
}
    
static inline unsigned long long trace_get_nsec(void)
{
     struct timespec tv;
     clock_gettime(CLOCK_REALTIME, &tv);
     return ((unsigned long long) tv.tv_sec * 1000000000) + tv.tv_nsec;
}

static inline void trace_increment_nesting_level(void)
{
    trace_current_nesting++;
}

static inline void trace_decrement_nesting_level(void)
{
    trace_current_nesting--;
}

static inline unsigned short trace_get_nesting_level(void)
{
    return trace_current_nesting;
}
    
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
