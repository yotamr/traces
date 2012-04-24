#include <getopt.h>
#include <signal.h>
#include <libgen.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <syslog.h>
#include <time.h>
#include <sys/sysinfo.h>

#include "config.h"
#include "list_template.h"
#include "filesystem.h"
#include "bool.h"
#include "trace_metadata_util.h"
#include "trace_parser.h"
#include "min_max.h"
#include "array_length.h"
#include "trace_lib.h"
#include "trace_user.h"

#define MAX_FILTER_SIZE (10)
#define METADATA_IOVEC_SIZE 2*(MAX_METADATA_SIZE/TRACE_RECORD_PAYLOAD_SIZE+1)

#define TRACE_FILE_MAX_RECORDS_PER_FILE        0x1000000

struct trace_mapped_metadata {
    struct iovec metadata_iovec[METADATA_IOVEC_SIZE];
    struct trace_record metadata_payload_record;
    unsigned long log_descriptor_count;
    unsigned long type_definition_count;
    unsigned int size;
    void *base_address;
    struct trace_log_descriptor *descriptors;
};
    
struct trace_mapped_records {
    struct trace_record *records;
    struct trace_records_mutable_metadata *mutab;
    struct trace_records_immutable_metadata *imutab;
    
    unsigned long long current_read_record;
    unsigned int last_flush_offset;

    unsigned long long next_flush_ts;
    unsigned int next_flush_record;
    unsigned int next_flush_offset;
	unsigned int old_generation;

    struct trace_record buffer_dump_record;
};

#define TRACE_BUFNAME_LEN (0x100)
#define MAX_BUFFER_COUNT (10)

struct trace_mapped_buffer {
    char name[TRACE_BUFNAME_LEN];
    void *records_buffer_base_address;
    unsigned long records_buffer_size;
    unsigned long last_metadata_offset;
    bool_t metadata_dumped;
    struct trace_mapped_records mapped_records[TRACE_BUFFER_NUM_RECORDS];
    struct trace_mapped_metadata metadata;
    unsigned short pid;
    unsigned int dead;
    unsigned long long process_time;
};

CREATE_LIST_PROTOTYPE(MappedBuffers, struct trace_mapped_buffer);
CREATE_LIST_IMPLEMENTATION(MappedBuffers, struct trace_mapped_buffer);

typedef char buffer_name_t[0x100];
CREATE_LIST_PROTOTYPE(BufferFilter, buffer_name_t);
CREATE_LIST_IMPLEMENTATION(BufferFilter, buffer_name_t);

#define TRACE_FILE_PREFIX "trace."

#define TRACE_METADATA_IOVEC_SIZE  (2*(MAX_METADATA_SIZE/TRACE_RECORD_PAYLOAD_SIZE+1))

#define TRACE_FILE_MAX_RECORDS_PER_LOGDIR        (TRACE_FILE_MAX_RECORDS_PER_FILE) * 10
#define TRACE_FILE_MAX_RECORDS_PER_CHUNK       0x10000

struct trace_record_file {
    unsigned long records_written;
    char filename[0x100];
    int fd;
};

enum operation_type {
    OPERATION_TYPE_DUMP_RECORDS,
};

struct trace_dumper_configuration_s {
    const char *logs_base;
    const char *attach_to_pid;
    struct trace_record_matcher_spec_s severity_filter[SEVERITY_FILTER_LEN];
    unsigned int header_written;
    unsigned int write_to_file;
    const char *fixed_output_filename;
    unsigned int online;
    unsigned int debug_online;
    unsigned int syslog;
    unsigned long long start_time;
    int no_color;
	struct trace_record_file record_file;
	unsigned int last_flush_offset;
    enum operation_type op_type;
	unsigned long long prev_flush_ts;
	unsigned long long next_flush_ts;
	unsigned long long ts_flush_delta;
    struct trace_parser parser;
    BufferFilter filtered_buffers;
    MappedBuffers mapped_buffers;
    struct iovec flush_iovec[1 + (3 * MAX_BUFFER_COUNT * TRACE_RECORD_BUFFER_RECS)];
};

static struct trace_dumper_configuration_s trace_dumper_configuration;

bool_t is_trace_shm_region(const char *shm_name)
{
    if (strncmp(shm_name, TRACE_SHM_ID, strlen(TRACE_SHM_ID)) == 0) {
        return TRUE;
    } else {
        return FALSE;
    }
}

pid_t get_pid_from_shm_name(const char *shm_name)
{
    char str_pid[10];
    shm_name += strlen(TRACE_SHM_ID);
    char *underscore = strstr(shm_name, "_");
    
    if (NULL == underscore) {
        return -1;
    }

    if ((unsigned long) (underscore - shm_name) >= sizeof(str_pid)) {
        return -1;
    }
    
    memcpy(str_pid, shm_name, underscore - shm_name);
    str_pid[underscore - shm_name] = '\0';
    return atoi(str_pid);
    
}

bool_t is_static_log_data_shm_region(const char *shm_name)
{
    if (strstr(shm_name, "static_trace_metadata") != NULL) {
        return TRUE;
    } else {
        return FALSE;
    }
}

bool_t is_dynamic_log_data_shm_region(const char *shm_name)
{
    if (strstr(shm_name, "dynamic_trace_data") != 0) {
        return TRUE;
    } else {
        return FALSE;
    }
}

static int dump_iovector_to_parser(struct trace_dumper_configuration_s *conf, struct trace_parser *parser, const struct iovec *iov, int iovcnt)
{
    int i;
    int rc;
    unsigned char accumulated_trace_record[sizeof(struct trace_record)];
    unsigned char *tmp_ptr = accumulated_trace_record;
    unsigned char *iovec_base_ptr;
    for (i = 0; i < iovcnt; i++) {
        iovec_base_ptr = iov[i].iov_base;
        while (1) {
            unsigned int remaining_rec = sizeof(struct trace_record) - (tmp_ptr - accumulated_trace_record);
            unsigned int copy_len = MIN(remaining_rec, iov[i].iov_len - (iovec_base_ptr - (unsigned char *) iov[i].iov_base));
            memcpy(tmp_ptr, iovec_base_ptr, copy_len);
            tmp_ptr += copy_len;
            iovec_base_ptr += copy_len;
            if (tmp_ptr - accumulated_trace_record == sizeof(struct trace_record)) {
                char formatted_record[10 * 1024];
                unsigned int was_record_formatted = 0;
                rc = TRACE_PARSER__process_next_from_memory(parser, (struct trace_record *) accumulated_trace_record, formatted_record, sizeof(formatted_record), &was_record_formatted);
                tmp_ptr = accumulated_trace_record;
                if (was_record_formatted) {
                    if (!conf->syslog) {
                        printf("%s\n", formatted_record);
                    } else {
                        syslog(LOG_DEBUG, "%s", formatted_record);
                    }
                }
                if (0 != rc) {
                    return -1;
                }
            }

            if ((unsigned char *)iovec_base_ptr - (unsigned char *)iov[i].iov_base == (unsigned int) iov[i].iov_len) {
                break;
            }
        }
    }
    
    return 0;
}

static int total_iovec_len(const struct iovec *iov, int iovcnt)
{
    int total = 0;
    int i;
    for (i = 0; i < iovcnt; i++) {
        total += iov[i].iov_len;
    }

    return total;
}
static int trace_dumper_write(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const struct iovec *iov, int iovcnt)
{
    int expected_bytes = total_iovec_len(iov, iovcnt);
    int rc = 0;
    if (conf->record_file.fd >= 0) {
        rc = writev(record_file->fd, iov, iovcnt);
        if (rc != expected_bytes) {
            return -1;
        }
        record_file->records_written += expected_bytes / sizeof(struct trace_record);
    }

    if (conf->online) {
        int parser_rc = dump_iovector_to_parser(conf, &conf->parser, iov, iovcnt);
        if (parser_rc != 0) {
            return -1;
        }
    }

    return expected_bytes;
}

static void init_metadata_iovector(struct trace_mapped_metadata *metadata, unsigned short pid)
{
    memset(&metadata->metadata_payload_record, 0, sizeof(metadata->metadata_payload_record));
    metadata->metadata_payload_record.rec_type = TRACE_REC_TYPE_METADATA_PAYLOAD;
    metadata->metadata_payload_record.termination = 0;
    metadata->metadata_payload_record.pid = pid;
    
    unsigned long remaining_length = metadata->size;
    unsigned int i;
    for (i = 0; i < TRACE_METADATA_IOVEC_SIZE / 2; i++) {
        if (remaining_length <= 0) {
            break;
        }
        metadata->metadata_iovec[i*2].iov_base = &metadata->metadata_payload_record;
        metadata->metadata_iovec[i*2].iov_len = TRACE_RECORD_HEADER_SIZE;
        metadata->metadata_iovec[i*2+1].iov_base = &((char *) metadata->base_address)[i * TRACE_RECORD_PAYLOAD_SIZE];
		metadata->metadata_iovec[i*2+1].iov_len = TRACE_RECORD_PAYLOAD_SIZE;
        remaining_length -= TRACE_RECORD_PAYLOAD_SIZE;
    }
}

#define SIMPLE_WRITE(__conf__, __data__, __size__) do {                   \
                                                                        \
        struct iovec __iov__ = {__data__, __size__}; rc = trace_dumper_write(conf, &conf->record_file, &__iov__, 1); } while (0);

static int write_metadata_header_start(struct trace_dumper_configuration_s *conf, struct trace_mapped_buffer *mapped_buffer)
{
    struct trace_record rec;
    int rc;
    rec.rec_type = TRACE_REC_TYPE_METADATA_HEADER;
    rec.termination = TRACE_TERMINATION_FIRST;
    rec.pid = mapped_buffer->pid;
    rec.ts = trace_get_nsec();
    rec.u.metadata.metadata_size_bytes = mapped_buffer->metadata.size;
    SIMPLE_WRITE(conf, &rec, sizeof(rec));
    if (rc != sizeof(rec)) {
        return -1;
    }
    
    return 0;
}


static int write_metadata_end(struct trace_dumper_configuration_s *conf, struct trace_mapped_buffer *mapped_buffer)
{
    struct trace_record rec;
    int rc;
	memset(&rec, 0, sizeof(rec));
	rec.rec_type = TRACE_REC_TYPE_METADATA_PAYLOAD;
	rec.termination = TRACE_TERMINATION_LAST;
    rec.pid = mapped_buffer->pid;
    rec.ts = trace_get_nsec();
    SIMPLE_WRITE(conf, &rec, sizeof(rec));
    if (rc != sizeof(rec)) {
        return -1;
    }

    return 0;
}

static int trace_dump_metadata(struct trace_dumper_configuration_s *conf, struct trace_mapped_buffer *mapped_buffer)
{
    struct trace_record rec;
    unsigned int num_records;
    int rc;

    mapped_buffer->metadata.metadata_payload_record.ts = trace_get_nsec();

    memset(&rec, 0, sizeof(rec));
    rc = write_metadata_header_start(conf, mapped_buffer);
    if (0 != rc) {
        return -1;
    }
    
    num_records = mapped_buffer->metadata.size / (TRACE_RECORD_PAYLOAD_SIZE) + ((mapped_buffer->metadata.size % (TRACE_RECORD_PAYLOAD_SIZE)) ? 1 : 0);
    rc = trace_dumper_write(conf, &conf->record_file, mapped_buffer->metadata.metadata_iovec, 2 * num_records);
    if ((unsigned int) rc != num_records * sizeof(struct trace_record)) {
        return -1;
    }

    rc = write_metadata_end(conf, mapped_buffer);
    return rc;
}

static int stat_pid(unsigned short pid, struct stat *stat_buf)
{
    char filename[0x100];
    snprintf(filename, sizeof(filename), "/proc/%d", pid);
    return stat(filename, stat_buf);
}


static int get_process_time(unsigned short pid, unsigned long long *curtime)
{
    struct stat stat_buf;
    int rc = stat_pid(pid, &stat_buf);
    if (0 != rc) {
        return -1;
    }

    *curtime = stat_buf.st_mtim.tv_sec * 1000000000;
    *curtime += stat_buf.st_mtim.tv_nsec;
    return 0;
}

static int delete_shm_files(unsigned short pid)
{
    INFO("Deleting shm files for pid", pid);
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

bool_t trace_should_filter(struct trace_dumper_configuration_s *conf __attribute__((unused)), const char *buffer_name)
{
    buffer_name_t filter;
    memset(filter, 0, sizeof(filter));
    strncpy(filter, buffer_name, sizeof(filter));
    int rc = BufferFilter__find_element(&conf->filtered_buffers, &filter);
    if (rc >= 0) {
        return TRUE;
    } else {
        return FALSE;
    }
}

static int map_buffer(struct trace_dumper_configuration_s *conf, pid_t pid)
{
    int static_fd, dynamic_fd;
    char dynamic_trace_filename[0x100];
    char static_log_data_filename[0x100];
    char full_dynamic_trace_filename[0x100];
    char full_static_log_data_filename[0x100];
    int rc;
    unsigned int dead = 0;
    snprintf(dynamic_trace_filename, sizeof(dynamic_trace_filename), "_trace_shm_%d_dynamic_trace_data", pid);
    snprintf(static_log_data_filename, sizeof(static_log_data_filename), "_trace_shm_%d_static_trace_metadata", pid);
    snprintf(full_dynamic_trace_filename, sizeof(full_dynamic_trace_filename), "%s/%s", SHM_PATH, dynamic_trace_filename);
    snprintf(full_static_log_data_filename, sizeof(full_static_log_data_filename), "%s/%s", SHM_PATH, static_log_data_filename);

    int trace_region_size = get_file_size(full_dynamic_trace_filename);
    if (trace_region_size <= 0) {
        ERROR("Unable to read region size");
        rc = -1;
        goto delete_shm_files;
    }

   int static_log_data_region_size = get_file_size(full_static_log_data_filename);
    if (static_log_data_region_size <= 0) {
        ERROR("Unable to read static region size: %s", static_log_data_filename);
        rc = -1;
        goto delete_shm_files;
    }

    dynamic_fd = open(full_dynamic_trace_filename, O_RDWR, 0);
    printf("opened (1) %s\n", full_dynamic_trace_filename);
    if (dynamic_fd < 0) {
        ERROR("Unable to open dynamic buffer %s: %s", dynamic_trace_filename, strerror(errno));
        rc = -1;
        goto delete_shm_files;
    }
    
    static_fd = open(full_static_log_data_filename, O_RDWR, 0);
    printf("opened (2) %s\n", full_static_log_data_filename);
    if (static_fd < 0) {
        ERROR("Unable to open static buffer: %s", strerror(errno));
        rc = -1;
        goto close_static;

    }

    void *mapped_dynamic_addr = mmap(NULL, trace_region_size, PROT_READ | PROT_WRITE, MAP_SHARED, dynamic_fd, 0);
    if (NULL == mapped_dynamic_addr) {
        ERROR("Unable to map log information buffer");
        rc = -1;
        goto close_dynamic;

    }
    
    void * mapped_static_log_data_addr = mmap(NULL, static_log_data_region_size, PROT_READ | PROT_WRITE, MAP_SHARED, static_fd, 0);

    if (NULL == mapped_static_log_data_addr) {
        ERROR("Unable to map static log area: %s", strerror(errno));
        rc = -1;
        goto unmap_dynamic;
    }
    
    struct trace_buffer *unmapped_trace_buffer = (struct trace_buffer *) mapped_dynamic_addr;
    struct trace_mapped_buffer *new_mapped_buffer;
    struct trace_metadata_region *static_log_data_region = (struct trace_metadata_region *) mapped_static_log_data_addr;
    
    if (trace_should_filter(conf, static_log_data_region->name)) {
        rc = 0;
        INFO("Filtering buffer", static_log_data_region->name);
        goto unmap_static;

    }
    
    if (0 != MappedBuffers__allocate_element(&conf->mapped_buffers)) {
        rc = -1;
        goto unmap_static;
        return -1;
    }

    MappedBuffers__get_element_ptr(&conf->mapped_buffers, MappedBuffers__element_count(&conf->mapped_buffers) - 1, &new_mapped_buffer);
    memset(new_mapped_buffer, 0, sizeof(*new_mapped_buffer));
    if (static_log_data_region_size > MAX_METADATA_SIZE) {
        ERROR("Error, metadata size %x too large", static_log_data_region_size);
        rc = -1;
        goto unmap_static;
    }

    new_mapped_buffer->records_buffer_base_address = mapped_dynamic_addr;
    new_mapped_buffer->records_buffer_size = trace_region_size;
    new_mapped_buffer->metadata.log_descriptor_count = static_log_data_region->log_descriptor_count;
    new_mapped_buffer->metadata.type_definition_count = static_log_data_region->type_definition_count;
    new_mapped_buffer->metadata.descriptors = (struct trace_log_descriptor *) static_log_data_region->data;
    new_mapped_buffer->metadata.size = static_log_data_region_size;
    new_mapped_buffer->metadata.base_address = mapped_static_log_data_addr;
    new_mapped_buffer->pid = (unsigned short) pid;
    new_mapped_buffer->metadata_dumped = FALSE;
    unsigned long long process_time;
    rc = get_process_time(pid, &process_time);
    if (0 != rc) {
        rc = 0;
        WARN("Process", pid, "no longer exists");
        dead = 1;
        process_time = 0;
    }

    new_mapped_buffer->process_time = process_time;
    relocate_metadata(static_log_data_region->base_address, mapped_static_log_data_addr, (char *) new_mapped_buffer->metadata.descriptors,
                      new_mapped_buffer->metadata.log_descriptor_count, new_mapped_buffer->metadata.type_definition_count);
    static_log_data_region->base_address = mapped_static_log_data_addr;
    init_metadata_iovector(&new_mapped_buffer->metadata, new_mapped_buffer->pid);
    strncpy(new_mapped_buffer->name, static_log_data_region->name, sizeof(new_mapped_buffer->name));
    unsigned int i;
    for (i = 0; i < TRACE_BUFFER_NUM_RECORDS; i++) {
        struct trace_mapped_records *mapped_records;

        mapped_records = &new_mapped_buffer->mapped_records[i];
        mapped_records->records = unmapped_trace_buffer->u._all_records[i].records;
        mapped_records->mutab = &unmapped_trace_buffer->u._all_records[i].mutab;
        mapped_records->imutab = &unmapped_trace_buffer->u._all_records[i].imutab;
        mapped_records->last_flush_offset = 0;
        if (dead) {
            mapped_records->current_read_record = 0;
        } else {
            mapped_records->current_read_record = mapped_records->mutab->current_record & mapped_records->imutab->max_records_mask;
        }
    }

    INFO("new process joined" ,"pid =", new_mapped_buffer->pid, "name =", new_mapped_buffer->name);
    rc = 0;
    goto exit;
    MappedBuffers__remove_element(&conf->mapped_buffers, MappedBuffers__element_count(&conf->mapped_buffers) - 1);
unmap_static:
    munmap(mapped_static_log_data_addr, static_log_data_region_size);
unmap_dynamic:
    munmap(mapped_dynamic_addr, trace_region_size);
close_dynamic:
    close(dynamic_fd);
close_static:
    close(static_fd);
delete_shm_files:
    delete_shm_files(pid);
exit:
    return rc;
}

static bool_t buffer_mapped(struct trace_dumper_configuration_s * conf, unsigned short pid)
{
    int i;
    for (i = 0; i < MappedBuffers__element_count(&conf->mapped_buffers); i++) {
        struct trace_mapped_buffer *mapped_buffer;
        MappedBuffers__get_element_ptr(&conf->mapped_buffers, i, &mapped_buffer);
        if (mapped_buffer->pid == pid) {
            return TRUE;
        }
    }

    return FALSE;
}

static int process_potential_trace_buffer(struct trace_dumper_configuration_s *conf, const char *shm_name)
{
    int rc = 0;
    if (!is_trace_shm_region(shm_name)) {
        return 0;
    }

    pid_t pid = get_pid_from_shm_name(shm_name);
    if (pid <= 0) {
        return -1;
    }

    if (is_dynamic_log_data_shm_region(shm_name) && !buffer_mapped(conf, pid)) {
        rc = map_buffer(conf, pid);
    }


    return rc;
}

static int map_new_buffers(struct trace_dumper_configuration_s *conf)
{
    DIR *dir;
    struct dirent *ent;
    int rc = 0;
    dir = opendir(SHM_PATH);

    if (dir == NULL) {
        return -1;
    }
    
    while (TRUE) {
        ent = readdir(dir);
        if (NULL == ent) {
            goto exit;
        }

        rc = process_potential_trace_buffer(conf, ent->d_name);
        if (0 != rc) {
            ERROR("Error processing trace buffer");
            continue;
        }
    }
exit:
    closedir(dir);
    return 0;
}

static bool_t process_exists(unsigned short pid) {
    struct stat buf;
    char filename[0x100];
    snprintf(filename, sizeof(filename), "/proc/%d", pid);
    int rc = stat(filename, &buf);
    if (0 == rc) {
        return TRUE;
    } else {
        return FALSE;
    }
}

static bool_t process_changed(struct trace_mapped_buffer *buffer)
{
    if (!process_exists(buffer->pid)) {
        return TRUE;
    }
    
    unsigned long long current_time;
    get_process_time(buffer->pid, &current_time);
    if (buffer->process_time == current_time) {
        return FALSE;
    } else {
        return TRUE;
    }
}

bool_t is_trace_file(const char *filename)
{
    if (strncmp(filename, TRACE_FILE_PREFIX, strlen(TRACE_FILE_PREFIX)) != 0) {
          return FALSE;
    } else {
        return TRUE;
    }
}

int get_trace_file_timestamp(const char *filename)
{
    if (!is_trace_file(filename)) {
        return -1;
    }
    
    char timestamp[50];
    strncpy(timestamp, filename + strlen(TRACE_FILE_PREFIX), sizeof(timestamp));
    char *tmp_ptr = index(timestamp, '.');
    if (NULL == tmp_ptr) {
        return -1;
    }

    *tmp_ptr = '\0';
    long int result = strtol(timestamp, (char **) NULL, 10);
    if (result == LONG_MAX || result == LONG_MIN) {
        return -1;
    }

    return result;
}


static int find_oldest_trace_file(struct trace_dumper_configuration_s *conf, char *filename, unsigned int filename_size)
{
    DIR *dir;
    struct dirent *ent;
    int min_timestamp = INT_MAX;
    int tmp_timestamp = 0;
    char tmp_filename[0x100];
    dir = opendir(conf->logs_base);

    if (dir == NULL) {
        return -1;
    }
    
    while (TRUE) {
        ent = readdir(dir);
        if (NULL == ent) {
            goto Exit;
        }

        tmp_timestamp = get_trace_file_timestamp(ent->d_name);
        if (tmp_timestamp < 0) {
            continue;
        }
        if (min_timestamp > tmp_timestamp) {
            min_timestamp = tmp_timestamp;
            snprintf(tmp_filename, sizeof(tmp_filename), "%s/%s", conf->logs_base, ent->d_name);
        }
    }

Exit:
    strncpy(filename, tmp_filename, filename_size);
    closedir(dir);
    return 0;
}

static long long total_records_in_logdir(struct trace_dumper_configuration_s *conf)
{
    DIR *dir;
    struct dirent *ent;
    long long total_bytes = 0;
    dir = opendir(conf->logs_base);

    if (dir == NULL) {
        return -1;
    }

    
    while (TRUE) {
        ent = readdir(dir);
        if (NULL == ent) {
            goto Exit;
        }
        
        if (!is_trace_file(ent->d_name)) {
            continue;
        }
        char full_filename[0x100];
        snprintf(full_filename, sizeof(full_filename), "%s/%s", conf->logs_base, ent->d_name);
        long long file_size = get_file_size(full_filename);
        if (file_size < 0) {
            closedir(dir);
            return -1;
        }

        total_bytes += file_size;
    }

Exit:
    closedir(dir);
    // If not a multiple of a trace record - return an error
    if (total_bytes % sizeof(struct trace_record)) {
        INFO(total_bytes, "is not a multiple of", sizeof(struct trace_record));
        return 0;
    }

    return total_bytes / sizeof(struct trace_record);    
}

static int delete_oldest_trace_file(struct trace_dumper_configuration_s *conf)
{
    char filename[0x100];
    int rc = find_oldest_trace_file(conf, filename, sizeof(filename));
    if (0 != rc) {
        return -1;
    }

    INFO("Deleting oldest trace file", filename);
    return unlink(filename);
}

#define for_each_mapped_records(_i_, _rid_, _mapped_buffer_, _mr_)      \
    for (({_i_ = 0; MappedBuffers__get_element_ptr(&conf->mapped_buffers, i, &_mapped_buffer_);}); _i_ < MappedBuffers__element_count(&conf->mapped_buffers); ({_i_++; MappedBuffers__get_element_ptr(&conf->mapped_buffers, i, &_mapped_buffer_);})) \
        for (({_rid_ = 0; _mr_ = &_mapped_buffer_->mapped_records[_rid_];}); _rid_ < TRACE_BUFFER_NUM_RECORDS; ({_rid_++; _mr_ = &_mapped_buffer_->mapped_records[_rid_];}))

#define for_each_mapped_buffer(_i_, _mapped_buffer_)      \
    for (({_i_ = 0; MappedBuffers__get_element_ptr(&conf->mapped_buffers, i, &_mapped_buffer_);}); _i_ < MappedBuffers__element_count(&conf->mapped_buffers); ({_i_++; MappedBuffers__get_element_ptr(&conf->mapped_buffers, i, &_mapped_buffer_);})) 



static void discard_buffer(struct trace_dumper_configuration_s *conf, struct trace_mapped_buffer *mapped_buffer)
{
    INFO("Discarding pid", mapped_buffer->pid, mapped_buffer->name);
    int rc = munmap(mapped_buffer->metadata.base_address, mapped_buffer->metadata.size);
    if (0 != rc) {
        ERROR("Error unmapping metadata for buffer", mapped_buffer->name);
        return;
    }

    rc = munmap(mapped_buffer->records_buffer_base_address, mapped_buffer->records_buffer_size);
    if (0 != rc) {
        ERROR("Error unmapping records for buffer", mapped_buffer->name);
        return;
    }

    delete_shm_files(mapped_buffer->pid);
    struct trace_mapped_buffer *tmp_mapped_buffer;
    int i;
    for_each_mapped_buffer(i, tmp_mapped_buffer) {
        if (mapped_buffer == tmp_mapped_buffer) {
            MappedBuffers__remove_element(&conf->mapped_buffers, i);
        }
    }
}


static int unmap_discarded_buffers(struct trace_dumper_configuration_s *conf)
{
    int i;
    struct trace_mapped_buffer *mapped_buffer;
    for_each_mapped_buffer(i, mapped_buffer) {
        if (!process_exists(mapped_buffer->pid) || process_changed(mapped_buffer)) {
            mapped_buffer->dead = 1;
        }
    }

    return 0;
}

static unsigned long long trace_get_walltime(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    return (((unsigned long long)tv.tv_sec) * 100000) + tv.tv_usec;
}

static long get_uptime(void)
{
    struct sysinfo info;
    sysinfo(&info);

    return info.uptime;
}

static int trace_write_header(struct trace_dumper_configuration_s *conf)
{
    struct utsname ubuf;
    struct trace_record rec;
    struct trace_record_file_header *file_header = &rec.u.file_header;
    int rc;
    
    memset(&rec, 0, sizeof(rec));
    memset(&ubuf, 0, sizeof(ubuf));
    uname(&ubuf);

    rec.rec_type = TRACE_REC_TYPE_FILE_HEADER;
	rec.termination = (TRACE_TERMINATION_LAST | TRACE_TERMINATION_FIRST);

	snprintf((char *)file_header->machine_id, sizeof(file_header->machine_id), "%s", ubuf.nodename);
    file_header->boot_time = (time(NULL) - get_uptime()) * 1000000;
	SIMPLE_WRITE(conf, &rec, sizeof(rec));
	if (rc != sizeof(rec)) {
		return -1;
    }

	return 0;
}

static int trace_open_file(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const char *filename_base)
{
    unsigned long long now;
    char filename[0x100];
    int rc;

    record_file->records_written = 0;
    now = trace_get_walltime() / 1000;

    if (conf->fixed_output_filename) {
        strncpy(filename, conf->fixed_output_filename, sizeof(filename));
    } else {
        snprintf(filename, sizeof(filename),
                 "%s/trace.%lld.dump", filename_base, now);
    }

    INFO("Opening trace file:", filename);
    record_file->fd = open(filename, O_WRONLY | O_CREAT, 0644);
    if (record_file->fd < 0) {
        fprintf(stderr, "Error opening %s for writing\n", filename);
        return -1;
    }

    rc = trace_write_header(conf);
    strncpy(record_file->filename, filename, sizeof(record_file->filename));
    return rc;
}

void calculate_delta(struct trace_mapped_records *mapped_records, unsigned int *delta, unsigned int *delta_a, unsigned int *delta_b)
{
    unsigned int last_written_record;

    last_written_record = mapped_records->mutab->current_record & mapped_records->imutab->max_records_mask;
    if (last_written_record == mapped_records->current_read_record) {
        *delta = 0;
        return;
    }    
        
    /* Calculate delta with wraparound considered */
    if (last_written_record > mapped_records->current_read_record) {
        *delta_a = last_written_record - mapped_records->current_read_record;
        *delta_b = 0;
    } else if (last_written_record < mapped_records->current_read_record) {
        *delta_a = mapped_records->imutab->max_records - mapped_records->current_read_record;
        *delta_b = last_written_record;
    }

    /* Cap on TRACE_FILE_MAX_RECORDS_PER_CHUNK */
    if (*delta_a + *delta_b > TRACE_FILE_MAX_RECORDS_PER_CHUNK) {
        if (*delta_a > TRACE_FILE_MAX_RECORDS_PER_CHUNK) {
            *delta_a = TRACE_FILE_MAX_RECORDS_PER_CHUNK;
            *delta_b = 0;
        }
        if (*delta_b > TRACE_FILE_MAX_RECORDS_PER_CHUNK - *delta_a) {
            *delta_b = TRACE_FILE_MAX_RECORDS_PER_CHUNK - *delta_a;
        }
    }

    *delta = *delta_a + *delta_b;
}

static void init_dump_header(struct trace_dumper_configuration_s *conf, struct trace_record *dump_header_rec,
                             unsigned long long cur_ts,
                             struct iovec **iovec, unsigned int *num_iovecs, unsigned int *total_written_records)
{
    memset(dump_header_rec, 0, sizeof(*dump_header_rec));
	*iovec = &conf->flush_iovec[(*num_iovecs)++];
	(*iovec)->iov_base = dump_header_rec;
	(*iovec)->iov_len = sizeof(*dump_header_rec);

    (*total_written_records)++;
    dump_header_rec->rec_type = TRACE_REC_TYPE_DUMP_HEADER;
	dump_header_rec->u.dump_header.prev_dump_offset = conf->last_flush_offset;
    dump_header_rec->ts = cur_ts;
}

static int dump_metadata_if_necessary(struct trace_dumper_configuration_s *conf, struct trace_mapped_buffer *mapped_buffer)
{
    if (!mapped_buffer->metadata_dumped) {
        mapped_buffer->last_metadata_offset = conf->record_file.records_written;
        int rc = trace_dump_metadata(conf, mapped_buffer);
        if (0 != rc) {
            ERROR("Error dumping metadata");
            mapped_buffer->last_metadata_offset = -1;
            return -1;
        }
    }
    
    mapped_buffer->metadata_dumped = TRUE;
    return 0;
}

static void init_buffer_chunk_record(struct trace_dumper_configuration_s *conf, struct trace_mapped_buffer *mapped_buffer,
                                     struct trace_mapped_records *mapped_records, struct trace_record_buffer_dump **bd,
                                     struct iovec **iovec, unsigned int *iovcnt, unsigned int delta, unsigned int delta_a,
                                     unsigned long long cur_ts, unsigned int total_written_records)
{
    memset(&mapped_records->buffer_dump_record, 0, sizeof(mapped_records->buffer_dump_record));
    mapped_records->buffer_dump_record.rec_type = TRACE_REC_TYPE_BUFFER_CHUNK;
    mapped_records->buffer_dump_record.ts = cur_ts;
    mapped_records->buffer_dump_record.termination = (TRACE_TERMINATION_LAST |
                                                      TRACE_TERMINATION_FIRST);
    mapped_records->buffer_dump_record.pid = mapped_buffer->pid;
    (*bd) = &mapped_records->buffer_dump_record.u.buffer_chunk;
    (*bd)->last_metadata_offset = mapped_buffer->last_metadata_offset;
    (*bd)->prev_chunk_offset = mapped_records->last_flush_offset;
    (*bd)->dump_header_offset = conf->last_flush_offset;
    (*bd)->ts = cur_ts;
    (*bd)->records = delta;
    (*bd)->severity_type = mapped_records->imutab->severity_type;
    mapped_records->next_flush_offset = conf->record_file.records_written + total_written_records;
    (*iovec) = &conf->flush_iovec[(*iovcnt)++];
    (*iovec)->iov_base = &mapped_records->buffer_dump_record;
    (*iovec)->iov_len = sizeof(mapped_records->buffer_dump_record);

    (*iovec) = &conf->flush_iovec[(*iovcnt)++];
    (*iovec)->iov_base = &mapped_records->records[mapped_records->current_read_record];
    (*iovec)->iov_len = TRACE_RECORD_SIZE * delta_a;
}

static int possibly_write_iovecs(struct trace_dumper_configuration_s *conf, unsigned int num_iovecs, unsigned int total_written_records, unsigned long long cur_ts)
{
    int i;
    int rid;
    struct trace_mapped_buffer *mapped_buffer;
    struct trace_mapped_records *mapped_records;
    if (num_iovecs > 1) {
        conf->last_flush_offset = conf->record_file.records_written;
		conf->prev_flush_ts = cur_ts;
		conf->next_flush_ts = cur_ts + conf->ts_flush_delta;

        int ret = trace_dumper_write(conf, &conf->record_file, conf->flush_iovec, num_iovecs);
		if ((unsigned int)ret != (total_written_records * sizeof(struct trace_record))) {
            return -1;
		}


		for_each_mapped_records(i, rid, mapped_buffer, mapped_records) {
			mapped_records->mutab->latest_flushed_ts = mapped_records->next_flush_ts;
			mapped_records->current_read_record =  mapped_records->next_flush_record;
			mapped_records->last_flush_offset = mapped_records->next_flush_offset;
		}
	}

    return 0;
}

static int trace_flush_buffers(struct trace_dumper_configuration_s *conf)
{
    struct trace_mapped_buffer *mapped_buffer;
    struct trace_mapped_records *mapped_records;
    unsigned long long cur_ts;
    struct trace_record dump_header_rec;
    struct iovec *iovec;
    unsigned int num_iovecs = 0;
    int i = 0, rid = 0;
    unsigned int total_written_records = 0;
    unsigned int delta, delta_a, delta_b;

	cur_ts = trace_get_nsec();
    init_dump_header(conf, &dump_header_rec, cur_ts, &iovec, &num_iovecs, &total_written_records);

	for_each_mapped_records(i, rid, mapped_buffer, mapped_records) {
		struct trace_record_buffer_dump *bd;
		struct trace_record *last_rec;
        int rc = dump_metadata_if_necessary(conf, mapped_buffer);
        if (0 != rc) {
            return rc;
        }
        
        calculate_delta(mapped_records, &delta, &delta_a, &delta_b);
		if (delta == 0) {
            if (mapped_buffer->dead) {
                discard_buffer(conf, mapped_buffer);
                return 0;
                break;
                if (conf->attach_to_pid) {
                    return -1;
                }
            } else {
                continue;
            }
        }

        init_buffer_chunk_record(conf, mapped_buffer, mapped_records, &bd, &iovec, &num_iovecs, delta, delta_a, cur_ts, total_written_records);
		last_rec = (struct trace_record *) (&mapped_records->records[mapped_records->current_read_record + delta_a - 1]);
		if (delta_b) {
			iovec = &conf->flush_iovec[num_iovecs++];
			iovec->iov_base = &mapped_records->records[0];
			iovec->iov_len = TRACE_RECORD_SIZE * delta_b;
			last_rec = (struct trace_record *) &mapped_records->records[delta_b - 1];
		}

        
		mapped_records->next_flush_ts = last_rec->ts;

		total_written_records += delta + 1;
		mapped_records->next_flush_record = mapped_records->current_read_record + delta;
		mapped_records->next_flush_record &= mapped_records->imutab->max_records_mask;
	}

	dump_header_rec.u.dump_header.total_dump_size = total_written_records - 1;
    dump_header_rec.u.dump_header.first_chunk_offset = conf->record_file.records_written + 1;

	if (cur_ts < conf->next_flush_ts) {
		return 0;
	}

    return possibly_write_iovecs(conf, num_iovecs, total_written_records, cur_ts);
}

static void close_record_file(struct trace_dumper_configuration_s *conf)
{
    close(conf->record_file.fd);
    conf->record_file.fd = -1;
    conf->last_flush_offset = 0;

    int i;
    struct trace_mapped_buffer *mapped_buffer;
    struct trace_mapped_records *mapped_records;
    conf->header_written = 0;
    int rid;

    for_each_mapped_records(i, rid, mapped_buffer, mapped_records) {
        mapped_records->last_flush_offset = 0;
        mapped_buffer->last_metadata_offset = 0;
        mapped_buffer->metadata_dumped = FALSE;
    }
}

static int rotate_trace_file_if_necessary(struct trace_dumper_configuration_s *conf)
{
    if (!conf->write_to_file || conf->fixed_output_filename) {
        return 0;
    }
    
    if (conf->record_file.records_written < TRACE_FILE_MAX_RECORDS_PER_FILE) {
        INFO("Records written:", conf->record_file.records_written, "Max records per file:", TRACE_FILE_MAX_RECORDS_PER_FILE);
        return 0;
    }

    close_record_file(conf);
    /* Reopen journal file */
    
    int rc = trace_open_file(conf, &conf->record_file, conf->logs_base);
    if (0 != rc) {
        ERROR("Unable to open trace file:", strerror(errno));
        return -1;
    }

    while (TRUE) {
        INFO(total_records_in_logdir(conf), TRACE_FILE_MAX_RECORDS_PER_LOGDIR);
        if (total_records_in_logdir(conf) > TRACE_FILE_MAX_RECORDS_PER_LOGDIR) {
            rc = delete_oldest_trace_file(conf);
            if (0 != rc) {
                return -1;
            }
        } else {
            break;
        }
    }
    
    return 0;
}

static int open_trace_file_if_necessary(struct trace_dumper_configuration_s *conf)
{
    if (conf->write_to_file && conf->record_file.fd < 0) {
        int rc = trace_open_file(conf, &conf->record_file, conf->logs_base);
        if (0 != rc) {
            ERROR("Unable to open trace file");
            return -1;
        }
    }

    return 0;
}
    
static int dump_records(struct trace_dumper_configuration_s *conf)
{
    int rc;
    while (1) {
        rc = open_trace_file_if_necessary(conf);
        if (rc != 0) {
            return -1;
        }
        
        rc = rotate_trace_file_if_necessary(conf);
        if (0 != rc) {
            return -1;
        }
        rc = trace_flush_buffers(conf);
        if (0 != rc) {
            return -1;
        }
        
        usleep(20000);
        if (!conf->attach_to_pid) {
            map_new_buffers(conf);
        }
        
        rc = unmap_discarded_buffers(conf);
        if (0 != rc) {
            return rc;
        }
    }
}

static int op_dump_records(struct trace_dumper_configuration_s *conf)
{
    int rc;
    if (!conf->attach_to_pid) {
        rc = map_new_buffers(conf);
    }  else {
        rc = map_buffer(conf, atoi(conf->attach_to_pid));
    }
    
    if (0 != rc) {
        ERROR("Error mapping buffers");
        return 1;
    }
    conf->start_time = trace_get_walltime();
    return dump_records(conf);

}
static int run_dumper(struct trace_dumper_configuration_s *conf)
{
    switch (conf->op_type) {
    case OPERATION_TYPE_DUMP_RECORDS:
        return op_dump_records(conf);
        break; 
    default:
        break;
    }

    return 0;
}


static const char usage[] = {
    "Usage: %s [params]                                                                        \n" \
    "                                                                                          \n" \
    " -h, --help                            Display this help message                                     \n" \
    " -f  --filter [buffer_name]            Filter out specified buffer name                              \n" \
    " -o  --online                          Show data from buffers as it arrives (slows performance)      \n" \
    " -w  --write-to-file[filename]         Write log records to file                                     \n" \
    " -b  --logdir                          Specify the base log directory trace files are written to     \n" \
    " -p  --pid [pid]                       Attach the specified process                                  \n" \
    " -d  --debug-online                    Display DEBUG records in online mode                          \n" \
    " -s  --syslog                          In online mode, write the entries to syslog instead of displaying them\n"
    "\n"};

static const struct option longopts[] = {
    { "help", 0, 0, 'h'},
	{ "filter", required_argument, 0, 'f'},
	{ "online", 0, 0, 'o'},
    { "debug-online", 0, 0, 'd'},
    { "logdir", required_argument, 0, 'b'},
	{ "no-color", 0, 0, 'n'},
    { "syslog", 0, 0, 's'},
    { "pid", required_argument, 0, 'p'},
    { "write", optional_argument, 0, 'w'},

	{ 0, 0, 0, 0}
};

static void print_usage(void)
{
    printf(usage, "trace_dumper");
}

static const char shortopts[] = "sw::p:hf:odb:n";

#define DEFAULT_LOG_DIRECTORY "/mnt/logs"
static void clear_mapped_records(struct trace_dumper_configuration_s *conf)
{
    MappedBuffers__init(&conf->mapped_buffers);
}

static void add_buffer_filter(struct trace_dumper_configuration_s *conf, char *buffer_name)
{
    buffer_name_t filter;
    memset(filter, 0, sizeof(filter));
    strncpy(filter, buffer_name, sizeof(filter));
    
    if (0 != BufferFilter__add_element(&conf->filtered_buffers, &filter)) {
        ERROR("Can't add buffer", buffer_name,  "%s to filter list");
    }
}

static int parse_commandline(struct trace_dumper_configuration_s *conf, int argc, char **argv)
{
    int o;
    while ((o = getopt_long(argc, argv, shortopts, longopts, 0)) != EOF) {
		switch (o) {
		case 'h':
			break;
		case 'f':
			add_buffer_filter(conf, optarg);
			break;
        case 'o':
            conf->online = 1;
            break;
        case 'b':
            conf->logs_base = optarg;
            break;
        case 'n':
            conf->no_color = 1;
            break;
        case 'd':
            conf->debug_online = 1;
            break;
        case 'p':
            conf->attach_to_pid = optarg;
            break;
        case 'w':
            conf->write_to_file = 1;
            conf->fixed_output_filename = optarg;
            break;
        case 's':
            conf->syslog = 1;
            break;
        case '?':
            print_usage();
            return -1;
            break;
        default:
            break;
        }
    }

    return 0;
}

#define ROTATION_COUNT 10
#define FLUSH_DELTA 5000;

static void parser_event_handler(trace_parser_t __attribute__((unused)) *parser, enum trace_parser_event_e __attribute__((unused))event, void __attribute__((unused))*event_data, void __attribute__((unused)) *arg)
{
}

static void init_dumper(struct trace_dumper_configuration_s *conf)
{
    clear_mapped_records(conf);
    
    conf->op_type = OPERATION_TYPE_DUMP_RECORDS;
    conf->logs_base = DEFAULT_LOG_DIRECTORY;
    conf->record_file.fd = -1;
    conf->ts_flush_delta = FLUSH_DELTA;
    TRACE_PARSER__from_external_stream(&conf->parser, parser_event_handler, NULL);
    TRACE_PARSER__set_indent(&conf->parser, TRUE);
    TRACE_PARSER__set_relative_ts(&conf->parser, TRUE);
    if (!conf->no_color) {
        TRACE_PARSER__set_color(&conf->parser, TRUE);
    } else {
        TRACE_PARSER__set_color(&conf->parser, TRUE);
    }
    if (conf->syslog) {
        openlog("traces", 0, 0);
        TRACE_PARSER__set_indent(&conf->parser, 0);
        TRACE_PARSER__set_color(&conf->parser, 0);
    }

    // TODO: Take care of severity
    unsigned int severity_mask = ((1 << TRACE_SEV_INFO) | (1 << TRACE_SEV_WARN) | (1 << TRACE_SEV_ERROR) | (1 << TRACE_SEV_FATAL));
    if (conf->debug_online) {
        severity_mask |= ((1 << TRACE_SEV_FUNC_TRACE) | (1 << TRACE_SEV_DEBUG));
        TRACE_PARSER__set_indent(&conf->parser, TRUE);
    } else {
        TRACE_PARSER__set_indent(&conf->parser, FALSE);
    }

    TRACE_PARSER__matcher_spec_from_severity_mask(severity_mask, conf->severity_filter, ARRAY_LENGTH(conf->severity_filter));
    TRACE_PARSER__set_filter(&conf->parser, conf->severity_filter);
}

void usr1_handler()
{
    if (trace_dumper_configuration.record_file.fd >= 0) {
        close_record_file(&trace_dumper_configuration);
    }
}

void usr2_handler()
{
    if (trace_dumper_configuration.record_file.fd >= 0) {
        close_record_file(&trace_dumper_configuration);
    }

    char snapshot_filename[0x100];
    char dir[0x100];
    char base[0x100];
    char orig_filename[0x100];
    strncpy(orig_filename, trace_dumper_configuration.record_file.filename, sizeof(orig_filename));
    char *dirname_ptr = dirname(orig_filename);
    strncpy(dir, dirname_ptr, sizeof(dir));
    strncpy(orig_filename, trace_dumper_configuration.record_file.filename, sizeof(orig_filename));
    char *basename_ptr = basename(orig_filename);
    strncpy(base, basename_ptr, sizeof(base));
    snprintf(snapshot_filename, sizeof(snapshot_filename), "%s/snapshot.%s", dir, base);
    int rc = rename(trace_dumper_configuration.record_file.filename, snapshot_filename);
    if (0 != rc) {
        ERROR("Error moving",  trace_dumper_configuration.record_file.filename, "to", snapshot_filename, "(", strerror(errno), ")");
    } else {
        INFO("Created snapshot file at", snapshot_filename);
    }
}

static void set_signal_handling(void)
{
    signal(SIGUSR1, usr1_handler);
    signal(SIGUSR2, usr2_handler);
}

int main(int argc, char **argv)
{
    struct trace_dumper_configuration_s *conf = &trace_dumper_configuration;
    memset(conf, 0, sizeof(*conf));
    if (0 != parse_commandline(conf, argc, argv)) {
        return 1;
    }

    init_dumper(&trace_dumper_configuration);
    set_signal_handling();
    if (!conf->write_to_file && !conf->online) {
        fprintf(stderr, "Must specify either -w or -o\n");
        print_usage();
        return 1;
    }
    return run_dumper(conf);
}
