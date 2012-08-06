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

#ifndef __TRACE_DEFS_H__
#define __TRACE_DEFS_H__

#include "config.h"

#ifdef __cplusplus
 extern "C" {
#endif

#define MAX_METADATA_SIZE (0x1000000)
#define TRACE_BUFFER_NUM_RECORDS (3)

     
#define TRACE_SEVERITY_DEF       \
     TRACE_SEV_X(0, INVALID)     \
     TRACE_SEV_X(1, FUNC_TRACE)  \
     TRACE_SEV_X(2, DEBUG)       \
     TRACE_SEV_X(3, INFO)        \
     TRACE_SEV_X(4, WARN)        \
     TRACE_SEV_X(5, ERROR)       \
     TRACE_SEV_X(6, FATAL)       \

enum trace_severity {
#define TRACE_SEV_X(num, name) \
	TRACE_SEV_##name  = num,

TRACE_SEVERITY_DEF
        TRACE_SEV__MIN = 1,
        TRACE_SEV__MAX = 6
#undef TRACE_SEV_X
};

static inline int trace_strcmp(const char *s1, const char *s2)
{
    /* Move s1 and s2 to the first differing characters 
       in each string, or the ends of the strings if they
       are identical.  */
    while (*s1 != '\0' && *s1 == *s2) {
        s1++;
        s2++;
    }
    /* Compare the characters as unsigned char and
       return the difference.  */
    const unsigned char uc1 = (*(const unsigned char *) s1);
    const unsigned char uc2 = (*(const unsigned char *) s2);
    return ((uc1 < uc2) ? -1 : (uc1 > uc2));
}
     
#define TRACE_SEV_X(num, name)                  \
    if (trace_strcmp(function_name, #name) == 0) { \
        return TRACE_SEV_##name;                \
    }
    
static inline enum trace_severity trace_function_name_to_severity(const char *function_name) {
    TRACE_SEVERITY_DEF;
    #undef TRACE_SEV_X
    return TRACE_SEV_INVALID;
}

enum trace_rec_type {
    TRACE_REC_TYPE_UNKNOWN = 0,
    TRACE_REC_TYPE_TYPED = 1,
    TRACE_REC_TYPE_FILE_HEADER = 2,
    TRACE_REC_TYPE_METADATA_HEADER = 3,
    TRACE_REC_TYPE_METADATA_PAYLOAD = 4,
    TRACE_REC_TYPE_DUMP_HEADER = 5,
    TRACE_REC_TYPE_BUFFER_CHUNK = 6,
    TRACE_REC_TYPE_END_OF_FILE = 7
};

enum trace_log_descriptor_kind {
    TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY = 0,
    TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE = 1,
    TRACE_LOG_DESCRIPTOR_KIND_EXPLICIT = 2,
};

#define TRACE_RECORD_SIZE           64
#define TRACE_RECORD_PAYLOAD_SIZE   44
#define TRACE_RECORD_HEADER_SIZE    (TRACE_RECORD_SIZE - TRACE_RECORD_PAYLOAD_SIZE)

     
enum trace_termination_type {
    TRACE_TERMINATION_LAST = 1,
    TRACE_TERMINATION_FIRST = 2
};

#define TRACE_MACHINE_ID_SIZE    0x18

static inline int trace_compare_generation(unsigned int a, unsigned int b)
{
    if (a >= 0xc0000000   &&  b < 0x40000000)
        return 1;
    if (b > a)
        return 1;
    if (b < a)
        return -1;
    return 0;
}

enum trace_file_type {
	TRACE_FILE_TYPE_JOURNAL = 1,
	TRACE_FILE_TYPE_SNAPSHOT = 2
};

 struct trace_enum_value;
     
 enum trace_type_id {
    TRACE_TYPE_ID_ENUM = 1,
    TRACE_TYPE_ID_RECORD = 2,
    TRACE_TYPE_ID_TYPEDEF = 3
};


struct trace_type_definition {
    enum trace_type_id type_id;
    unsigned int member_count;
    const char *type_name;
    union  {
        // void * is used to allow static initlization of the union in C++, which does not support designated initializors
        void *params;
        struct trace_enum_value *enum_values;
    };
};

 struct trace_enum_value {
    const char *name;
    unsigned int value;
};

struct trace_record {
    /* 20 bytes header */
    unsigned long long ts;
    unsigned short int pid;
    unsigned short int tid;
    short nesting;
    unsigned termination:2;
    unsigned reserved:6;
    unsigned severity:4;
    unsigned rec_type:4;
    unsigned int generation;
    
    /* 44 bytes payload */
    union trace_record_u {
        unsigned char payload[TRACE_RECORD_PAYLOAD_SIZE];
        struct trace_record_typed {
            unsigned int log_id;
            unsigned char payload[0];
        } typed;
        struct trace_record_file_header {
            unsigned char machine_id[TRACE_MACHINE_ID_SIZE];
            unsigned long long boot_time;
        } file_header;
        struct trace_record_metadata {
            unsigned int metadata_size_bytes;
        } metadata;
        struct trace_record_dump_header {
            unsigned int prev_dump_offset;
            unsigned int total_dump_size;
            unsigned int first_chunk_offset;
        } dump_header;
        struct trace_record_buffer_dump {
            unsigned int last_metadata_offset;
            unsigned int prev_chunk_offset;
            unsigned int dump_header_offset;
            unsigned long long ts;
            unsigned int records;
            unsigned int severity_type;
        } buffer_chunk;
    } __attribute__((packed)) u;
} __attribute__((packed));
     
enum trace_param_desc_flags {
    TRACE_PARAM_FLAG_NUM_8    = 0x001,
    TRACE_PARAM_FLAG_NUM_16   = 0x002,
    TRACE_PARAM_FLAG_NUM_32   = 0x004,
    TRACE_PARAM_FLAG_NUM_64   = 0x008,
    TRACE_PARAM_FLAG_VARRAY   = 0x010,
    TRACE_PARAM_FLAG_CSTR     = 0x020,
    
    TRACE_PARAM_FLAG_STR      = 0x040,
    TRACE_PARAM_FLAG_BLOB     = 0x080,
    
    TRACE_PARAM_FLAG_UNSIGNED = 0x100,
    TRACE_PARAM_FLAG_HEX      = 0x200,
    TRACE_PARAM_FLAG_ZERO     = 0x400,
    TRACE_PARAM_FLAG_ENUM     = 0x800,
    TRACE_PARAM_FLAG_NESTED_LOG   = 0x1000,
    TRACE_PARAM_FLAG_ENTER    = 0x2000,
    TRACE_PARAM_FLAG_LEAVE    = 0x4000,
    TRACE_PARAM_FLAG_TYPEDEF  = 0x8000,
    TRACE_PARAM_FLAG_NAMED_PARAM  = 0x10000,
    TRACE_PARAM_FLAG_RECORD  = 0x20000,
    TRACE_PARAM_FLAG_DOUBLE  = 0x40000,
};

struct trace_param_descriptor {
	unsigned long flags;
    unsigned long type_id;
    const char *param_name;
    union {
        const char *str;
        const char *const_str;
        const char *type_name;
    };
};

struct trace_log_descriptor {
    enum trace_log_descriptor_kind kind;
    enum trace_severity severity;
    struct trace_param_descriptor *params;
};

struct trace_metadata_region {
    char name[0x100];
    void *base_address;
    unsigned long log_descriptor_count;
    unsigned long type_definition_count;
    char data[0];
};
     
#ifdef __cplusplus
}
#endif

#endif 
