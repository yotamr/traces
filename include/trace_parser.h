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

#ifndef __TRACE_PARSER_H__
#define __TRACE_PARSER_H__

#include "list_template.h"
#include <stdio.h>
#include "trace_defs.h"

enum trace_parser_failure_e {
    TRACE_PARSER_NO_METADATA,
};

struct trace_parser_buffer_context {
    struct trace_metadata_region *metadata;
    unsigned long metadata_size;
    unsigned long current_metadata_offset;
    unsigned long metadata_read;
    struct trace_log_descriptor *descriptors;
    struct trace_type_definition *types;
    char name[0x100];
    unsigned int id;
};

#define MAX_ACCUMULATORS (100)
#define MAX_ACCUMULATED_DATA (2048 * 20)
struct trace_record_accumulator {
    char accumulated_data[MAX_ACCUMULATED_DATA];
    unsigned int data_offset;
    unsigned short int tid;
    unsigned long long ts;
};

CREATE_LIST_PROTOTYPE(BufferParseContextList, struct trace_parser_buffer_context)
CREATE_LIST_PROTOTYPE(RecordsAccumulatorList, struct trace_record_accumulator)

struct parser_complete_typed_record {
    struct trace_record *record;
    struct trace_parser_buffer_context *buffer;
};

struct trace_file_info {
    char filename[0x100];
    char machine_id[0x100];
    long boot_time;
    long long current_offset;
    long long end_offset;
    int fd;
    void *file_base;
};

enum trace_parser_event_e {
    TRACE_PARSER_COMPLETE_TYPED_RECORD_PROCESSED,
    TRACE_PARSER_MATCHED_RECORD,
    TRACE_PARSER_SEARCHING_METADATA,
    TRACE_PARSER_OPERATION_IN_PROGRESS,
    TRACE_PARSER_UNKNOWN_RECORD_ENCOUNTERED,
    TRACE_PARSER_FOUND_METADATA,
};

enum trace_input_stream_type {
    TRACE_INPUT_STREAM_TYPE_NONSEEKABLE,
    TRACE_INPUT_STREAM_TYPE_SEEKABLE_FILE
};

#define RECORD_DUMP_CONTEXTS (150)
struct record_dump_context_s {
    long long start_offset;
    long long current_offset;
    long long end_offset;
};

struct buffer_dump_context_s {
    struct record_dump_context_s record_dump_contexts[RECORD_DUMP_CONTEXTS];
    long long end_offset;
    long long previous_dump_offset;
    long long file_offset;
    unsigned int num_chunks;
};

struct operation_progress_status_s {
    long long records_processed;
    long long current_offset;
};

enum trace_record_matcher_type {
    TRACE_MATCHER_TRUE,
    TRACE_MATCHER_FALSE,
    TRACE_MATCHER_OR,
    TRACE_MATCHER_AND,
    TRACE_MATCHER_NOT,
    TRACE_MATCHER_PID,
    TRACE_MATCHER_TID,
    TRACE_MATCHER_TIMERANGE,
    TRACE_MATCHER_LOGID,
    TRACE_MATCHER_SEVERITY,
    TRACE_MATCHER_FUNCTION,
    TRACE_MATCHER_TYPE,
    TRACE_MATCHER_LOG_PARAM_VALUE,
    TRACE_MATCHER_LOG_NAMED_PARAM_VALUE,
    TRACE_MATCHER_PROCESS_NAME,
    TRACE_MATCHER_NESTING,
    TRACE_MATCHER_CONST_SUBSTRING,
};

typedef struct trace_record_matcher_spec_s trace_record_matcher_spec_s;
struct trace_record_matcher_spec_s {
    enum trace_record_matcher_type type;
    union trace_record_matcher_data_u {
        unsigned short pid;
        unsigned short tid;
        unsigned int log_id;
        unsigned severity;
        struct trace_time_range {
            unsigned long long start;
            unsigned long long end;
        } time_range;

        char function_name[0x100];
        char type_name[0x100];
        char process_name[0x100];
        char const_string[0x100];
        unsigned long long param_value;
        unsigned short nesting;
        
        struct trace_matcher_named_param_value {
            char param_name[0x100];
            unsigned long long param_value;
        } named_param_value;
            
        struct trace_record_matcher_binary_operator_params {
            struct trace_record_matcher_spec_s *a, *b;
        } binary_operator_parameters;
        
        struct trace_record_matcher_unary_operator_params {
            struct trace_record_matcher_spec_s *param;
        } unary_operator_parameters;
    } u;
};

struct trace_parser;
typedef void (*trace_parser_event_handler_t)(struct trace_parser *parser, enum trace_parser_event_e event, void *event_data, void *arg);
typedef struct trace_parser {
    struct trace_file_info file_info;
    BufferParseContextList buffer_contexts;
    RecordsAccumulatorList records_accumulators;
    struct buffer_dump_context_s buffer_dump_context;
    trace_parser_event_handler_t event_handler;
    unsigned long long max_ts;
    void *arg;
    FILE *out_file;
    int color;
    int compact_traces;
    int show_timestamp;
    int always_hex;
    int indent;
    int relative_ts;
    bool_t wait_for_input;
    int inotify_fd;
    int inotify_descriptor;
    int show_field_names;
    bool_t cancel_ongoing_operation;
    struct trace_record_matcher_spec_s record_filter;
    unsigned int ignored_records_count;
    enum trace_input_stream_type stream_type;
} trace_parser_t;

#define SEVERITY_FILTER_LEN (21)
int TRACE_PARSER__from_file(trace_parser_t *parser, bool_t wait_for_input, const char *filename, trace_parser_event_handler_t event_handler, void *arg);
int TRACE_PARSER__process_previous_record_from_file(trace_parser_t *parser);
int TRACE_PARSER__process_next_record_from_file(trace_parser_t *parser);
void TRACE_PARSER__from_external_stream(trace_parser_t *parser, trace_parser_event_handler_t event_handler, void *arg);
void TRACE_PARSER__fini(trace_parser_t *parser);
void TRACE_PARSER__set_color(trace_parser_t *parser, int has_color);
void TRACE_PARSER__set_compact_traces(trace_parser_t *parser, int compact_traces);
void TRACE_PARSER__set_show_timestamp(trace_parser_t *parser, int show_timestamp);
void TRACE_PARSER__set_indent(trace_parser_t *parser, int indent);
void TRACE_PARSER__set_wait_for_input(trace_parser_t *parser, int wait_for_input);
void TRACE_PARSER__set_always_hex(trace_parser_t *parser, int always_hex);
void TRACE_PARSER__set_verbose(trace_parser_t *parser, int verbose);
void TRACE_PARSER__set_show_field_names(trace_parser_t *parser, int show_field_names);
void TRACE_PARSER__set_relative_ts(trace_parser_t *parser, int relative_ts);
int TRACE_PARSER__dump_all_metadata(trace_parser_t *parser);
void TRACE_PARSER__set_filter(trace_parser_t *parser, struct trace_record_matcher_spec_s *filter);
int TRACE_PARSER__find_next_record_by_expression(trace_parser_t *parser, struct trace_record_matcher_spec_s *expression);
int TRACE_PARSER__find_previous_record_by_expression(trace_parser_t *parser, struct trace_record_matcher_spec_s *expression);
int TRACE_PARSER__format_typed_record(trace_parser_t *parser, struct trace_parser_buffer_context *context, struct trace_record *record, char *formatted_record, unsigned int formatted_record_size);
void TRACE_PARSER__cancel_ongoing_operation(trace_parser_t *parser);

int TRACE_PARSER__dump(trace_parser_t *parser);
int TRACE_PARSER__dump_statistics(trace_parser_t *parser);
int TRACE_PARSER__process_next_from_memory(trace_parser_t *parser, struct trace_record *rec, char *formatted_record, unsigned int formatted_record_size, unsigned int *record_formatted);
long long TRACE_PARSER__seek(trace_parser_t *parser, long long offset, int whence);
unsigned long long TRACE_PARSER__seek_to_time(trace_parser_t *parser, unsigned long long ts, int *error_occurred);
int TRACE_PARSER__matcher_spec_from_severity_mask(unsigned int severity_mask, struct trace_record_matcher_spec_s filter[], unsigned int filter_count);

#endif /* __TRACE_PARSER_H__ */
