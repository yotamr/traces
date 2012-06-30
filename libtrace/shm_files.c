#include "shm_files.h"
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include "trace_defs.h"

int delete_shm_files(unsigned short pid)
{
    char dynamic_trace_filename[0x100];
    char static_log_data_filename[0x100];
    char full_dynamic_trace_filename[0x100];
    char full_static_log_data_filename[0x100];
    int rc;
    int tmp_rc;
    unsigned int i;
    snprintf(dynamic_trace_filename, sizeof(dynamic_trace_filename), "_trace_shm_%d_dynamic_trace_data", pid);
    snprintf(full_dynamic_trace_filename, sizeof(full_dynamic_trace_filename), "%s/%s", SHM_PATH, dynamic_trace_filename);
    snprintf(full_static_log_data_filename, sizeof(full_static_log_data_filename), "%s/%s", SHM_PATH, static_log_data_filename);

    
    rc = unlink(full_dynamic_trace_filename);
    for (i = 0; i < TRACE_MAX_OBJS_PER_PROCESS; i++) {
        snprintf(static_log_data_filename, sizeof(static_log_data_filename), "_trace_shm_%d_%d_static_trace_metadata", pid, i);
        snprintf(full_static_log_data_filename, sizeof(full_static_log_data_filename), "%s/%s", SHM_PATH, static_log_data_filename);
        tmp_rc = unlink(full_static_log_data_filename);
        if (tmp_rc != 0) {
            if (errno == ENOENT) {
                rc = 0;
                break;
            } else {
                rc |= tmp_rc;
                break;
            }
        }
    }

    return rc;
}

