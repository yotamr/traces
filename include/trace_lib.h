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
#include <stdlib.h>
#ifdef __repr__
#undef __repr__
#endif
    
extern struct trace_log_descriptor __static_log_information_start;
extern unsigned int __local_obj_key __attribute__ ((visibility ("internal")));
struct trace_buffer;
    
#define __repr__ _trace_represent(unsigned int *buf_left, struct trace_record *_record, struct trace_record **__record_ptr, unsigned char **typed_buf)
    unsigned short int trace_get_pid(void);
    unsigned short int trace_get_tid(void);
    unsigned long long trace_get_nsec(void);
    void trace_increment_nesting_level(void);
    void trace_decrement_nesting_level(void);
    void trace_decrement_nesting_level(void);
    unsigned short trace_get_nesting_level(void);
    unsigned short trace_get_nesting_level(void);
    struct trace_record *trace_get_record(enum trace_severity severity, unsigned int *generation);
    struct trace_buffer *get_current_trace_buffer(void);
    unsigned int trace_allocate_obj_key(void);
    
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
    union {
        struct trace_records _all_records[TRACE_BUFFER_NUM_RECORDS];
        struct {
            struct trace_records _funcs;
            struct trace_records _debug;
            struct trace_records _other;
        } records;
    } u;
};


#ifdef __cplusplus
}
#endif
#endif
