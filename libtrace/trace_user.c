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
int trace_obj_key;
int __local_obj_key __attribute__ ((visibility ("internal")));
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

#define ALLOC_STRING(dest, source)                      \
    do {                                                \
    unsigned int str_size = __builtin_strlen(source) + 1;   \
    __builtin_memcpy(*string_table, source, str_size); \
    dest = *string_table;                               \
    *string_table += str_size;      \
    } while(0);                                              


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

static void copy_log_params_to_allocated_buffer(struct trace_log_descriptor *log_desc, struct trace_param_descriptor **params,
                                                char **string_table)
{
    struct trace_param_descriptor *param = log_desc->params;
    while (param->flags != 0) {
        __builtin_memcpy(*params, param, sizeof(struct trace_param_descriptor));
        if (param->str) {
            ALLOC_STRING((*params)->str, param->str);
        }

        if (param->param_name) {
            ALLOC_STRING((*params)->param_name, param->param_name);
        }

        (*params)++;
        param++;
    }

    // Copy the sentinel param
    __builtin_memcpy(*params, param, sizeof(struct trace_param_descriptor));
    (*params)++;
}


static void copy_log_descriptors_to_allocated_buffer(unsigned int log_descriptor_count, struct trace_log_descriptor *log_desc, struct trace_param_descriptor *params,
                                                     char **string_table)
    
{
    unsigned int i;
    for (i = 0; i < log_descriptor_count; i++) {
        struct trace_log_descriptor *orig_log_desc = &__static_log_information_start + i;
        memcpy(log_desc, orig_log_desc, sizeof(*log_desc));
        log_desc->params = params;
        copy_log_params_to_allocated_buffer(orig_log_desc, &params, string_table);
        log_desc++;
    }
}

static void copy_enum_values_to_allocated_buffer(struct trace_type_definition *type_definition, struct trace_enum_value **enum_values,
                                                 char **string_table)
{
    struct trace_enum_value *enum_value = type_definition->enum_values;
    while (enum_value->name != NULL) {
        memcpy(*enum_values, enum_value, sizeof(*enum_value));
        ALLOC_STRING((*enum_values)->name, enum_value->name);
        (*enum_values)++;
        enum_value++;
    }

    // Copy the sentinel enum value
    memcpy(*enum_values, enum_value, sizeof(*enum_value));
    (*enum_values)++;
}

static void copy_type_definitions_to_allocated_buffer(struct trace_type_definition *type_definition, struct trace_enum_value *enum_values,
                                                      char **string_table)
{
    struct trace_type_definition **type = &__type_information_start;
    while (*type) {
        memcpy(type_definition, *type, sizeof(*type_definition));
        ALLOC_STRING(type_definition->type_name, (*type)->type_name);
        type_definition->enum_values = enum_values;
        switch ((*type)->type_id) {
        case TRACE_TYPE_ID_ENUM:
            copy_enum_values_to_allocated_buffer(*type, &enum_values, string_table);
            break;
        case TRACE_TYPE_ID_RECORD:
            break;
        case TRACE_TYPE_ID_TYPEDEF:
            break;
        default:
            break;
        }
        
        type_definition++;
        type++;
    }
}

static void copy_metadata_to_allocated_buffer(unsigned int log_descriptor_count, struct trace_log_descriptor *log_desc, struct trace_param_descriptor *params,
                                              struct trace_type_definition *type_definition, struct trace_enum_value *enum_values,
                                              char **string_table)
{
    copy_log_descriptors_to_allocated_buffer(log_descriptor_count, log_desc, params, string_table);
    copy_type_definitions_to_allocated_buffer(type_definition, enum_values, string_table);
}

static void copy_log_section_shared_area(int shm_fd, const char *buffer_name,
                                         unsigned int log_descriptor_count,
                                         unsigned int log_param_count,
                                         unsigned int type_definition_count,
                                         unsigned int enum_value_count,
                                         unsigned int alloc_size,
                                         unsigned int obj_key)
{
    void *mapped_addr = mmap(NULL, alloc_size, PROT_WRITE, MAP_SHARED, shm_fd, 0);
    ASSERT(mapped_addr != NULL);
    struct trace_metadata_region *metadata_region = (struct trace_metadata_region *) mapped_addr;
    struct trace_log_descriptor *log_desc = (struct trace_log_descriptor *) metadata_region->data;
    struct trace_type_definition *type_definition = (struct trace_type_definition *)((char *) log_desc + (sizeof(struct trace_log_descriptor) * log_descriptor_count));
    struct trace_param_descriptor *params = (struct trace_param_descriptor *)((char *) type_definition + (type_definition_count * sizeof(struct trace_type_definition)));
    struct trace_enum_value *enum_values = (struct trace_enum_value *) ((char *) params + (log_param_count * sizeof(struct trace_param_descriptor)));
    char *string_table = (char *) enum_values + (enum_value_count * sizeof(struct trace_enum_value));

    strncpy(metadata_region->name, buffer_name, sizeof(metadata_region->name));
    metadata_region->obj_key = obj_key;
    metadata_region->base_address = mapped_addr;
    metadata_region->log_descriptor_count = log_descriptor_count;
    metadata_region->type_definition_count = type_definition_count;
    copy_metadata_to_allocated_buffer(log_descriptor_count, log_desc, params,
                                      type_definition, enum_values,
                                      &string_table);
}

static void param_alloc_size(struct trace_param_descriptor *params, unsigned int *alloc_size, unsigned int *total_params)
{
    while (params->flags != 0) {
        if (params->str) {
            int len = strlen(params->str) + 1;
            *alloc_size += len;
        }

        if (params->param_name) {
            int len = strlen(params->param_name) + 1;
            *alloc_size += len;
        }

        *alloc_size += sizeof(*params);
        (*total_params)++;
        params++;
    }

    // Account for the sentinel param
    *alloc_size += sizeof(*params);
    (*total_params)++;
}

static void enum_values_alloc_size(struct trace_enum_value *values, unsigned int *enum_value_count,
                                       unsigned int *alloc_size)
{
    while (values->name != NULL) {
        *alloc_size += sizeof(*values);
        *alloc_size += strlen(values->name) + 1;
        (*enum_value_count)++;
        values++;
    }

    // Account for senitnel
    (*enum_value_count)++;
    *alloc_size += sizeof(*values);
}

static void type_definition_alloc_size(struct trace_type_definition *type, unsigned int *enum_value_count,
                                       unsigned int *alloc_size)
{
    *alloc_size += sizeof(*type);
    *alloc_size += strlen(type->type_name) + 1;
    switch (type->type_id) {
    case TRACE_TYPE_ID_ENUM:
        enum_values_alloc_size(type->enum_values, enum_value_count, alloc_size);
        break;
    case TRACE_TYPE_ID_RECORD:
        break;
    case TRACE_TYPE_ID_TYPEDEF:
        break;
    default:
        break;
    }
}
    
static void type_alloc_size(struct trace_type_definition **type_start, unsigned int *type_definition_count, unsigned int *enum_value_count,
                            unsigned int *alloc_size)
{
    *type_definition_count = 0;
    *enum_value_count = 0;
    
    struct trace_type_definition **type = type_start;
    while (*type) {
        (*type_definition_count)++;
        type_definition_alloc_size(*type, enum_value_count, alloc_size);
        type++;
    }
}

static void static_log_alloc_size(unsigned int log_descriptor_count, unsigned int *total_params,
                                  unsigned int *type_definition_count, unsigned int *enum_value_count,
                                  unsigned int *alloc_size)
{
    unsigned int i;
    *alloc_size = 0;
    *total_params = 0;
    for (i = 0; i < log_descriptor_count; i++) {
        struct trace_log_descriptor *element = &__static_log_information_start + i;
        *alloc_size += sizeof(*element);
        param_alloc_size(element->params, alloc_size, total_params);
    }

    
    type_alloc_size(&__type_information_start, type_definition_count, enum_value_count, alloc_size);
}

static void map_static_log_data(const char *buffer_name, unsigned int obj_key)
{
    char shm_name[0x100];
    unsigned long log_descriptor_count = &__static_log_information_end - &__static_log_information_start;
    unsigned int alloc_size;
    unsigned int total_log_descriptor_params;
    unsigned int type_definition_count;
    unsigned int enum_value_count;
    static_log_alloc_size(log_descriptor_count, &total_log_descriptor_params, &type_definition_count, &enum_value_count, &alloc_size);
    snprintf(shm_name, sizeof(shm_name), "%s%s%d_%d_static_trace_metadata", SHM_PATH, TRACE_SHM_ID, getpid(), obj_key);
    int shm_fd = open(shm_name, O_CREAT | O_RDWR, 0660);
    if (shm_fd < 0) {
        return;
    }
    ASSERT(shm_fd >= 0);
    alloc_size = (alloc_size + 63) & ~63;
    int rc = ftruncate(shm_fd, sizeof(struct trace_metadata_region) + alloc_size);
    ASSERT(0 == rc);
    copy_log_section_shared_area(shm_fd, buffer_name, log_descriptor_count, total_log_descriptor_params,
                                 type_definition_count, enum_value_count,
                                 sizeof(struct trace_metadata_region) + alloc_size, obj_key);

}

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


static inline unsigned int trace_get_obj_key(void)
{
    unsigned int __obj_key =__sync_fetch_and_add(&trace_obj_key, 1);
    if (__obj_key >= TRACE_MAX_OBJS_PER_PROCESS) {
        abort();
    }

    __local_obj_key = __obj_key;
    return __obj_key;
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

static int TRACE__register_buffer(const char *buffer_name)
{
    unsigned int obj_key = trace_get_obj_key();
    map_static_log_data(buffer_name, obj_key);
    
    if (!current_trace_buffer) {
        map_dynamic_log_buffers();
    }
    return 0;
}

static void get_exec_name(char *exec_name, unsigned int exec_name_size)
{
    char exec_path[512];
    int rc = readlink("/proc/self/exe", exec_path, sizeof(exec_path) - 1);
    if (rc < 0) {
        ASSERT(0);
    }

    exec_path[rc] = '\0';

    strncpy(exec_name, basename(exec_path), exec_name_size);    
}

static void TRACE__init(void) __attribute__((constructor));
static void TRACE__init(void)
{
    char buffer_name[512];
    get_exec_name(buffer_name, sizeof(buffer_name));
    TRACE__register_buffer(buffer_name);
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

int trace_buffer_allocated(void) {
    if (current_trace_buffer) {
        return 1;
    } else {
        return 0;
    }   
}

void TRACE__fini(void)
{
    current_trace_buffer = NULL;
    delete_shm_files(getpid());
}
