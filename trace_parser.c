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
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include "min_max.h"
#include "array_length.h"
#include "trace_defs.h"
#include "list_template.h"
#include "trace_metadata_util.h"
#include "trace_parser.h"
#include "cached_file.h"

CREATE_LIST_IMPLEMENTATION(BufferParseContextList, struct trace_parser_buffer_context)
CREATE_LIST_IMPLEMENTATION(RecordsAccumulatorList, struct trace_record_accumulator)

#define MAX_ULLONG	18446744073709551615ULL

#define TRACE_SECOND (1000000000)
#define TRACE_MINUTE (TRACE_SECOND * 60)
#define TRACE_HOUR   (TRACE_MINUTE * 60)
#define TRACE_DAY    (TRACE_HOUR * 24)
#define TRACE_YEAR   (TRACE_DAY * 365)

#define _B_BLACK(x)        "\033[40m" x
#define _F_GREY(x)         "\033[1;24;30m" x
#define _F_WHITE(x)        "\033[0;37m" x
#define _F_GREEN(x)        "\033[0;32m" x
#define _F_MAGENTA(x)      "\033[0;35m" x
#define _F_WHITE_BOLD(x)   "\033[1;37m" x 
#define _F_GREEN_BOLD(x)   "\033[1;32m" x 
#define _F_YELLOW_BOLD(x)  "\033[1;33m" x
#define _F_RED_BOLD(x)     "\033[1;31m" x
#define _F_CYAN_BOLD(x)    "\033[1;36m" x
#define _F_BLUE_BOLD(x)    "\033[1;34m" x
#define _F_MAGENTA_BOLD(x) "\033[1;35m" x
#define _ANSI_DEFAULTS(x)  "\033[0;39;49m" x

#define B_BLACK(x)        parser->color ? _B_BLACK(x) : x
#define F_GREY(x)         parser->color ? _F_GREY(x) : x
#define F_WHITE(x)        parser->color ? _F_WHITE(x) : x
#define F_GREEN(x)        parser->color ? _F_GREEN(x) : x
#define F_MAGENTA(x)      parser->color ? _F_MAGENTA(x) : x
#define F_WHITE_BOLD(x)   parser->color ? _F_WHITE_BOLD(x) : x
#define F_GREEN_BOLD(x)   parser->color ? _F_GREEN_BOLD(x) : x
#define F_YELLOW_BOLD(x)  parser->color ? _F_YELLOW_BOLD(x) : x
#define F_RED_BOLD(x)     parser->color ? _F_RED_BOLD(x) : x
#define F_CYAN_BOLD(x)    parser->color ? _F_CYAN_BOLD(x) : x
#define F_BLUE_BOLD(x)    parser->color ? _F_BLUE_BOLD(x) : x
#define F_MAGENTA_BOLD(x) parser->color ? _F_MAGENTA_BOLD(x) : x
#define ANSI_DEFAULTS(x)  parser->color ? _ANSI_DEFAULTS(x) : x

static int read_next_record(trace_parser_t *parser, struct trace_record *record)
{
    int rc;
    rc = cached_file__read(&parser->file_info.file_handle, record, sizeof(*record));
    if (rc == 0) {
        parser->buffer_dump_context.file_offset++;
        record->rec_type = TRACE_REC_TYPE_END_OF_FILE;
        record->ts = 0;
        return 0;
    }
    
    if (rc != sizeof(*record)) {
        return -1;
    }

    return 0;
}

void trace_parser_init(trace_parser_t *parser, trace_parser_event_handler_t event_handler, void *arg, enum trace_input_stream_type stream_type)
{
    memset(parser, 0, sizeof(*parser));
    parser->event_handler = event_handler;
    parser->arg = arg;
    parser->stream_type = stream_type;
    cached_file__init(&parser->file_info.file_handle);
    BufferParseContextList__init(&parser->buffer_contexts);
    parser->record_filter.type = TRACE_MATCHER_TRUE;
    RecordsAccumulatorList__init(&parser->records_accumulators);
}

void TRACE_PARSER__set_color(trace_parser_t *parser, int has_color)
{
    parser->color = has_color;
}

void TRACE_PARSER__always_hex(trace_parser_t *parser, int always_hex)
{
    parser->always_hex = always_hex;
}


static bool_t match_severity_with_match_expression(struct trace_record_matcher_spec_s *matcher, enum trace_severity severity);

void TRACE_PARSER__set_filter(trace_parser_t *parser, struct trace_record_matcher_spec_s *filter)
{
    memcpy(&parser->record_filter, filter, sizeof(parser->record_filter));
    if (match_severity_with_match_expression(filter, TRACE_SEV_FUNC_TRACE)) {
        TRACE_PARSER__set_indent(parser, 1);
    } else {
        TRACE_PARSER__set_indent(parser, 0);
    }
}

void TRACE_PARSER__set_relative_ts(trace_parser_t *parser, int relative_ts)
{
    parser->relative_ts = relative_ts;
}

void TRACE_PARSER__set_indent(trace_parser_t *parser, int indent)
{
    parser->indent = indent;
}

static int read_file_header(trace_parser_t *parser, struct trace_record *record) {
    int rc = read_next_record(parser, record);
    if (0 != rc) {
        return -1;
    }

    if (record->rec_type != TRACE_REC_TYPE_FILE_HEADER) {
        return -1;
    }

    return 0;
}

#define TRACE_SEV_X(v, str) [v] = #str,
const char *sev_to_str[] = {
	TRACE_SEVERITY_DEF
};
#undef TRACE_SEV_X

static struct trace_parser_buffer_context *get_buffer_context_by_pid(trace_parser_t *parser, unsigned short pid)
{
    int i;
    struct trace_parser_buffer_context *context;
    for (i = 0; i < BufferParseContextList__element_count(&parser->buffer_contexts); i++) {
        BufferParseContextList__get_element_ptr(&parser->buffer_contexts, i, &context);
        if (context->id == pid) {
            return context;
        }
    }

    return NULL;
}

static int free_buffer_context_by_pid(trace_parser_t *parser, unsigned short pid)
{
    int i;
    struct trace_parser_buffer_context *context;
    for (i = 0; i < BufferParseContextList__element_count(&parser->buffer_contexts); i++) {
        BufferParseContextList__get_element_ptr(&parser->buffer_contexts, i, &context);
        if (context->id == pid) {
            free(context->metadata);
            BufferParseContextList__remove_element(&parser->buffer_contexts, i);
            return 0;
        }
    }

    return -1;
}

static int metadata_info_started(trace_parser_t *parser, struct trace_record *rec)
{
    struct trace_parser_buffer_context *context = get_buffer_context_by_pid(parser, rec->pid);

    if (context) {        
        free_buffer_context_by_pid(parser, rec->pid);
    }

    struct trace_parser_buffer_context new_context;
    new_context.id = rec->pid;
    new_context.metadata_size = rec->u.metadata.metadata_size_bytes;
    if (new_context.metadata_size > MAX_METADATA_SIZE) {
        return -1;
    }
    
    new_context.metadata = malloc(new_context.metadata_size);
    if (NULL == new_context.metadata) {
        return -1;
    }

    new_context.current_metadata_offset = 0;
    BufferParseContextList__add_element(&parser->buffer_contexts, &new_context);

    return 0;
}

static int append_metadata(struct trace_parser_buffer_context *context, struct trace_record *rec)
{
    unsigned int remaining = context->metadata_size - context->current_metadata_offset;
    if (remaining == 0) {
        return -1;
    }
    memcpy(((char *)context->metadata) + context->current_metadata_offset, rec->u.payload, MIN(remaining, TRACE_RECORD_PAYLOAD_SIZE));
    context->current_metadata_offset += MIN(remaining, TRACE_RECORD_PAYLOAD_SIZE);
    return 0;
}

static int accumulate_metadata(trace_parser_t *parser, struct trace_record *rec)
{
    struct trace_parser_buffer_context *context = get_buffer_context_by_pid(parser, rec->pid);
    if (NULL == context) {
        return 0;
    }
    
    if (rec->termination & TRACE_TERMINATION_LAST) {
        // Reached end of accumulation. The accumulated offset should be identical to the total size of the metadata
        if (context->metadata_size != context->current_metadata_offset) {
            return -1;
        }

        relocate_metadata(context->metadata->base_address, context->metadata, context->metadata->data, context->metadata->log_descriptor_count, context->metadata->type_definition_count);
        context->descriptors = (struct trace_log_descriptor *) context->metadata->data;
        context->types = (struct trace_type_definition *) ((char *) context->metadata->data + (sizeof(struct trace_log_descriptor)) * context->metadata->log_descriptor_count);
        strncpy(context->name, context->metadata->name, sizeof(context->name));
        return 0;
    } else {
        return append_metadata(context, rec);
    }
}

static struct trace_record_accumulator *get_accumulator(trace_parser_t *parser, struct trace_record *rec)
{
    int i;
    struct trace_record_accumulator *accumulator;
    for (i = 0; i < RecordsAccumulatorList__element_count(&parser->records_accumulators); i++) {
        RecordsAccumulatorList__get_element_ptr(&parser->records_accumulators, i, &accumulator);
        if (accumulator->tid == rec->tid) {
            return accumulator;
        }
    }

    return NULL;
}

static void free_accumulator(trace_parser_t *parser, struct trace_record *rec)
{
    int i;
    struct trace_record_accumulator *accumulator;
    for (i = 0; i < RecordsAccumulatorList__element_count(&parser->records_accumulators); i++) {
        RecordsAccumulatorList__get_element_ptr(&parser->records_accumulators, i, &accumulator);
        if (accumulator->tid == rec->tid) {
            RecordsAccumulatorList__remove_element(&parser->records_accumulators, i);
            return;
        }
    }
}

static struct trace_record *accumulate_record(trace_parser_t *parser, struct trace_record *rec, int forward)
{
    struct trace_record_accumulator *accumulator = get_accumulator(parser, rec);
    if ((accumulator == NULL) && rec->termination == (TRACE_TERMINATION_FIRST | TRACE_TERMINATION_LAST)) {
        return rec;
    }

    if (NULL == accumulator) {
        if (!(rec->termination & TRACE_TERMINATION_FIRST)) {
            return NULL;
        }

        int rc = RecordsAccumulatorList__allocate_element(&parser->records_accumulators);
        if (0 != rc) {
            return NULL;
        }

        
        RecordsAccumulatorList__get_element_ptr(&parser->records_accumulators, RecordsAccumulatorList__last_element_index(&parser->records_accumulators), &accumulator);
        accumulator->tid = rec->tid;
        accumulator->data_offset = TRACE_RECORD_HEADER_SIZE;

        memcpy(accumulator->accumulated_data, (char *) rec, TRACE_RECORD_HEADER_SIZE);
    }

    if (accumulator->data_offset + TRACE_RECORD_PAYLOAD_SIZE >= sizeof(accumulator->accumulated_data)) {
        return NULL;
    }

    if (forward) {
        memcpy(accumulator->accumulated_data + accumulator->data_offset, rec->u.payload, TRACE_RECORD_PAYLOAD_SIZE);
    } else {
        memmove(accumulator->accumulated_data + TRACE_RECORD_HEADER_SIZE + sizeof(rec->u.payload), (char *) rec, accumulator->data_offset);
    }
    
    accumulator->data_offset += sizeof(rec->u.payload);

    if ((rec->termination & TRACE_TERMINATION_LAST && forward) ||
        (rec->termination & TRACE_TERMINATION_FIRST && !forward)) {
        return (struct trace_record *) accumulator->accumulated_data;
    } else {
        return NULL;
    }
}

struct function_entry_count {
    char name[256];
    unsigned int entry_count;
    unsigned int leave_count;
};


struct function_stats {
    struct function_entry_count functions[0x10000];
    unsigned int count;
    unsigned long long function_byte_count;
    unsigned long long debug_byte_count;
    unsigned int inside_record_entry;
};

static void dump_stats(struct function_stats *stats)
{
    unsigned int i;
    printf("Number of stats: %d\n", stats->count);
    for (i = 0; i < stats->count; i++) {
        printf("Entry %s: %d\n", stats->functions[i].name, stats->functions[i].entry_count);
        printf("Leave %s: %d\n", stats->functions[i].name, stats->functions[i].leave_count);
    }

    printf("Function entry records byte count: %lld\n", stats->function_byte_count);
    printf("Debug records byte count: %lld\n", stats->debug_byte_count);
}

#define MAX_FUNCTION_COUNT

static int find_function_stats(struct function_stats *stats, const char *name, struct function_entry_count **out)
{
    unsigned int i;
    for (i = 0; i < stats->count; i++) {
        if (strcmp(stats->functions[i].name, name) == 0) {
            *out = &stats->functions[i];
            return 0;
        }
    }

    return -1;
}

struct dump_context_s {
    int tail;
    int current_severity;
    char formatted_record[1024 * 20];
};

void format_timestamp(trace_parser_t *parser, unsigned long long ts, char *timestamp, unsigned int timestamp_size)
{
    if (parser->relative_ts) {
        // TODO: Not really relative, is it?
        snprintf(timestamp, timestamp_size, "%llu", ts);
    } else {
        time_t seconds = ts / TRACE_SECOND;
        char fmt_time[200];
        strncpy(fmt_time, ctime(&seconds), sizeof(fmt_time));
        fmt_time[strlen(fmt_time) - 1] = '\0';
        snprintf(timestamp, timestamp_size, "%s:%-10llu", fmt_time, ts % TRACE_SECOND);
    }
}

#define APPEND_FORMATTED_TEXT(...) do { char _tmpbuf[0x200]; snprintf(_tmpbuf, sizeof(_tmpbuf), __VA_ARGS__);     \
                                        unsigned int _srclen = strlen(_tmpbuf);                                   \
                                              if (total_length + _srclen >= formatted_record_size - 1) return -1; \
                                        memcpy(formatted_record + total_length, _tmpbuf, _srclen);                \
                                        total_length += _srclen;                                                  \
                                       } while (0);
#define SIMPLE_APPEND_FORMATTED_TEXT(source) do {                             \
      unsigned int _srclen = strlen(source);                                  \
      if (total_length + _srclen >= formatted_record_size - 1) return -1;     \
      memcpy(formatted_record + total_length, source, _srclen);               \
      total_length += _srclen;                                                \
    } while (0);
    
static void get_type(struct trace_parser_buffer_context *context, const char *type_name, struct trace_type_definition **type)
{
    struct trace_type_definition *tmp_type = context->types;
    unsigned int i = 0;
    for (i = 0; i < context->metadata->type_definition_count; i++) {
        if (strcmp(tmp_type->type_name, type_name) == 0) {
            *type = tmp_type;
            return;
        }

        tmp_type++;
    }

    *type = NULL;
}

static void get_enum_val_name(trace_parser_t *parser, struct trace_parser_buffer_context *context, struct trace_param_descriptor *param, unsigned int value, char *val_name, unsigned int val_name_size)
{
    struct trace_type_definition *enum_def;
    struct trace_enum_value *enum_value;
    get_type(context, param->type_name, &enum_def);
    if (enum_def == NULL) {
        snprintf(val_name, val_name_size, "%s", F_BLUE_BOLD("<? enum>"));
        return;
    }

    enum_value = enum_def->enum_values;
    while (enum_value->name) {
        if (enum_value->value == value) {
            snprintf(val_name, val_name_size, F_BLUE_BOLD("%s"), enum_value->name);
            return;
        }

        enum_value++;
    }

    snprintf(val_name, val_name_size, "%s", F_BLUE_BOLD("<? enum>"));
    return;
}

int TRACE_PARSER__format_typed_record(trace_parser_t *parser, struct trace_parser_buffer_context *context, struct trace_record *record, char *formatted_record, unsigned int formatted_record_size)
{
    struct trace_log_descriptor *log_desc;
    struct trace_param_descriptor *param;
    char *buffer_name = context->name;
    char timestamp[0x100];
    unsigned int total_length = 0;

    format_timestamp(parser, record->ts, timestamp, sizeof(timestamp));
    unsigned int metadata_index = record->u.typed.log_id;

    const char *severity_str;
    if (TRACE_SEV__MIN <= record->severity &&  TRACE_SEV__MAX >= record->severity)
		severity_str = sev_to_str[record->severity];
	else
		severity_str = "???";

    
    switch (record->severity) {
    case TRACE_SEV_FUNC_TRACE: severity_str = F_GREY("-----"); break;
    case TRACE_SEV_DEBUG: severity_str = F_WHITE("DEBUG"); break;
    case TRACE_SEV_INFO: severity_str = F_GREEN_BOLD("INFO "); break;
    case TRACE_SEV_WARN: severity_str = F_YELLOW_BOLD("WARN "); break;
    case TRACE_SEV_ERROR: severity_str = F_RED_BOLD("ERROR"); break;
    case TRACE_SEV_FATAL: severity_str = F_RED_BOLD("FATAL"); break;

    default: break;
    }


    if (parser->color) {
        APPEND_FORMATTED_TEXT("%s " _F_MAGENTA("%-20s ") _ANSI_DEFAULTS("%s [") _F_BLUE_BOLD("%5d") _ANSI_DEFAULTS("]") _F_GREY(" : ") _ANSI_DEFAULTS(""),
                              severity_str, buffer_name, timestamp, record->tid);
    } else {
        APPEND_FORMATTED_TEXT("%s %-20s %s [%5d] : ",
                              severity_str, buffer_name, timestamp, record->tid);
    }

	if (!context) {
		SIMPLE_APPEND_FORMATTED_TEXT("<?>");
		goto exit;
	}

    unsigned char *pdata = record->u.typed.payload;
    
    if (metadata_index >= context->metadata->log_descriptor_count) {
        APPEND_FORMATTED_TEXT("L? %d", metadata_index);
        goto exit;
    }

    log_desc = &context->descriptors[metadata_index];
    enum trace_log_descriptor_kind trace_kind = log_desc->kind;
    int first = 1;
    const char *delimiter = " ";
    if (trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY) {
        delimiter = ", ";
    }

    if (parser->indent) {
        int i;
        if (record->nesting < 0) {
            record->nesting = 0;
        }

        for (i = 0; i < record->nesting; i++) {
            SIMPLE_APPEND_FORMATTED_TEXT("    ");
        }
    }

    for (param = log_desc->params; (param->flags != 0); param++) {
        if (trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY && first) {
            SIMPLE_APPEND_FORMATTED_TEXT("--> ");
        } else if (trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE && first) {
            SIMPLE_APPEND_FORMATTED_TEXT("<-- ");
        }

        if (param->flags & TRACE_PARAM_FLAG_NAMED_PARAM) {
            SIMPLE_APPEND_FORMATTED_TEXT(F_WHITE_BOLD(""));
            SIMPLE_APPEND_FORMATTED_TEXT(param->param_name);
            SIMPLE_APPEND_FORMATTED_TEXT(" = ");
        }
        
        if (param->flags & TRACE_PARAM_FLAG_CSTR) {
            if (param->const_str) {
                if (((trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY) ||
                     (trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE)) && first) {
                    SIMPLE_APPEND_FORMATTED_TEXT(F_YELLOW_BOLD(""));
                    SIMPLE_APPEND_FORMATTED_TEXT(param->const_str);
                    SIMPLE_APPEND_FORMATTED_TEXT(ANSI_DEFAULTS("("));

                    first = 0;
                    if ((param + 1)->flags == 0) {
                        SIMPLE_APPEND_FORMATTED_TEXT(")");
                    }

                    continue;
                } else {
                    SIMPLE_APPEND_FORMATTED_TEXT(param->const_str);
                }

                if ((param + 1)->flags != 0) {
                    SIMPLE_APPEND_FORMATTED_TEXT(ANSI_DEFAULTS(""));
                    SIMPLE_APPEND_FORMATTED_TEXT(delimiter);
                }
                continue;
            } else {
                SIMPLE_APPEND_FORMATTED_TEXT("<cstr?>");
            }
        } else if (param->flags & TRACE_PARAM_FLAG_VARRAY) {
            if (param->flags & TRACE_PARAM_FLAG_STR) {
                SIMPLE_APPEND_FORMATTED_TEXT(F_CYAN_BOLD("\""));
            }
			
            while (1) {
				unsigned char sl = (*(unsigned char *)pdata);
				unsigned char len = sl & 0x7f;
				unsigned char continuation = sl & 0x80;
				char strbuf[255];
                
				memcpy(strbuf, pdata + 1, len);
				strbuf[len] = 0;
				pdata += sizeof(len) + len;
				if (param->flags & TRACE_PARAM_FLAG_STR) {
                    SIMPLE_APPEND_FORMATTED_TEXT(F_CYAN_BOLD(""));
                    SIMPLE_APPEND_FORMATTED_TEXT(strbuf);
                    SIMPLE_APPEND_FORMATTED_TEXT(ANSI_DEFAULTS(""));
				}

                if (param->flags & TRACE_PARAM_FLAG_STR && !continuation) {
                    SIMPLE_APPEND_FORMATTED_TEXT(F_CYAN_BOLD(""));
                    SIMPLE_APPEND_FORMATTED_TEXT("\"");
                    SIMPLE_APPEND_FORMATTED_TEXT(ANSI_DEFAULTS(""));
                    SIMPLE_APPEND_FORMATTED_TEXT(delimiter);
                }

                if (!continuation) {
                    break;
                }

            }
        }
        
        if (param->flags & TRACE_PARAM_FLAG_ENUM) {
            char enum_val_name[100];
            get_enum_val_name(parser, context, param, (*(unsigned int *)pdata), enum_val_name, sizeof(enum_val_name));
            SIMPLE_APPEND_FORMATTED_TEXT(enum_val_name);
            if ((param + 1)->flags != 0)
                SIMPLE_APPEND_FORMATTED_TEXT(delimiter);
            
            SIMPLE_APPEND_FORMATTED_TEXT(ANSI_DEFAULTS(""));
            pdata += sizeof(int);
        }
        
        if (param->flags & TRACE_PARAM_FLAG_NUM_8) {
            const char *fmt_str = "%hh";
            unsigned short v;

            v = (*(unsigned short *)pdata);
            pdata += sizeof(v);

            if (param->flags & TRACE_PARAM_FLAG_UNSIGNED)
                fmt_str = "%hhu";
            else if (param->flags & TRACE_PARAM_FLAG_ZERO)
                fmt_str = "%08hhx";
            else if ((param->flags & TRACE_PARAM_FLAG_HEX))
                fmt_str = "0x%hhx";

            SIMPLE_APPEND_FORMATTED_TEXT(F_CYAN_BOLD(""));
            APPEND_FORMATTED_TEXT(fmt_str, v);
            if ((param + 1)->flags != 0)
                SIMPLE_APPEND_FORMATTED_TEXT(delimiter);
            
            SIMPLE_APPEND_FORMATTED_TEXT(ANSI_DEFAULTS(""));
        }
        
        if (param->flags & TRACE_PARAM_FLAG_NUM_16) {
            const char *fmt_str = "%h";
            unsigned short v;

            v = (*(unsigned short *)pdata);
            pdata += sizeof(v);

            if (param->flags & TRACE_PARAM_FLAG_UNSIGNED)
                fmt_str = "%hu";
            else if (param->flags & TRACE_PARAM_FLAG_ZERO)
                fmt_str = "%08hx";
            else if (param->flags & TRACE_PARAM_FLAG_HEX)
                fmt_str = "0x%hx";

            SIMPLE_APPEND_FORMATTED_TEXT(F_CYAN_BOLD(""));
            APPEND_FORMATTED_TEXT(fmt_str, v);
            if ((param + 1)->flags != 0)
                SIMPLE_APPEND_FORMATTED_TEXT(delimiter);
            
            SIMPLE_APPEND_FORMATTED_TEXT(ANSI_DEFAULTS(""));
        }

        if (param->flags & TRACE_PARAM_FLAG_NUM_32) {
            const char *fmt_str = "%d";
            unsigned int v;

            v = (*(unsigned int *)pdata);
            pdata += sizeof(v);

            if (param->flags & TRACE_PARAM_FLAG_UNSIGNED)
                fmt_str = "%u";
            else if (param->flags & TRACE_PARAM_FLAG_ZERO)
                fmt_str = "%08x";
            else if (param->flags & TRACE_PARAM_FLAG_HEX)
                fmt_str = "0x%x";

            SIMPLE_APPEND_FORMATTED_TEXT(F_CYAN_BOLD(""));
            APPEND_FORMATTED_TEXT(fmt_str, v);
            if ((param + 1)->flags != 0)
                SIMPLE_APPEND_FORMATTED_TEXT(delimiter);
            
            SIMPLE_APPEND_FORMATTED_TEXT(ANSI_DEFAULTS(""));
        }

        if (param->flags & TRACE_PARAM_FLAG_NUM_64) {
            const char *fmt_str = "%lld";
            unsigned long long v;

            v = (*(unsigned long long *)pdata);
            pdata += sizeof(v);

            if (param->flags & TRACE_PARAM_FLAG_UNSIGNED)
                fmt_str = "%llu";
            else if (param->flags & TRACE_PARAM_FLAG_ZERO)
                fmt_str = "%016llx";
            else if (param->flags & TRACE_PARAM_FLAG_HEX)
                fmt_str = "0x%llx";

            SIMPLE_APPEND_FORMATTED_TEXT(F_CYAN_BOLD(""));
            APPEND_FORMATTED_TEXT(fmt_str, v);
            if ((param + 1)->flags != 0)
                SIMPLE_APPEND_FORMATTED_TEXT(delimiter);
            
            SIMPLE_APPEND_FORMATTED_TEXT(ANSI_DEFAULTS(""));
        }
        
        if ((param + 1)->flags == 0 && (trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY || trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE)) {
            SIMPLE_APPEND_FORMATTED_TEXT(ANSI_DEFAULTS(")"));
        }
    }

exit:
    SIMPLE_APPEND_FORMATTED_TEXT(ANSI_DEFAULTS(""));
    formatted_record[total_length] = '\0';
    return 0;
}

static int process_typed_record(trace_parser_t *parser, bool_t accumulate_forward, struct trace_record *rec, struct trace_record **out_record, struct trace_parser_buffer_context **buffer)
{
    struct trace_record *complete_record = accumulate_record(parser, rec, accumulate_forward);
    if (!complete_record) {
        return -1;
    }

    *buffer = get_buffer_context_by_pid(parser, complete_record->pid);
    complete_record->termination |= TRACE_TERMINATION_LAST;
    *out_record = complete_record;

    return 0;
}

typedef int (*typed_record_processor_t)(trace_parser_t *parser, struct trace_record *record, void *arg);

static void ignore_next_n_records(trace_parser_t *parser, unsigned int ignore_count)
{
    parser->ignored_records_count = ignore_count;
}

static bool_t match_record_dump_with_match_expression(struct trace_record_matcher_spec_s *matcher, struct trace_record *record, struct trace_parser_buffer_context *buffer_context);

static void process_buffer_chunk_record(trace_parser_t *parser, struct trace_record *buffer_chunk)
{
    struct trace_record_buffer_dump *bd = &buffer_chunk->u.buffer_chunk;
    
    if (bd->severity_type) {
        if (parser->stream_type == TRACE_INPUT_STREAM_TYPE_NONSEEKABLE && !(match_record_dump_with_match_expression(&parser->record_filter, buffer_chunk, NULL))) {
            ignore_next_n_records(parser, bd->records);
        }
    }
}

static long long trace_file_current_offset(trace_parser_t *parser)
{
    if (cached_file__is_open(&parser->file_info.file_handle) < 0) {
        return -1;
    }

    return TRACE_PARSER__seek(parser, 0, SEEK_CUR);
}

static int read_record_at_offset(trace_parser_t *parser, long long offset, struct trace_record *record)
{
    long long new_offset;
    new_offset = TRACE_PARSER__seek(parser, offset, SEEK_SET);
    if (-1 == new_offset) {
        return -1;
    }

    return read_next_record(parser, record);
}

static int process_metadata(trace_parser_t *parser, struct trace_record *record)
{
    long long original_offset = trace_file_current_offset(parser);
    struct trace_record_buffer_dump *buffer_chunk;
    buffer_chunk = &record->u.buffer_chunk;
    int rc = 0;
    
    long long new_offset;
    new_offset = TRACE_PARSER__seek(parser, buffer_chunk->last_metadata_offset, SEEK_SET);
    if (-1 == new_offset) {
        rc = -1;
        goto Exit;
    }

    struct trace_record tmp_record;
    rc = read_next_record(parser, &tmp_record);
    if (0 != rc) {
        goto Exit;
    }

    if (tmp_record.rec_type != TRACE_REC_TYPE_METADATA_HEADER) {
        rc = -1;
        goto Exit;
    }

    rc = metadata_info_started(parser, &tmp_record);
    if (0 != rc) {
        goto Exit;
    }

    do {
        rc = read_next_record(parser, &tmp_record);
        if (0 != rc) {
            goto Exit;
        }

        if (tmp_record.rec_type != TRACE_REC_TYPE_METADATA_PAYLOAD) {
            goto Exit;
        }

        rc = accumulate_metadata(parser, &tmp_record);
        if (0 != rc) {
            goto Exit;
        }
    } while (!(tmp_record.termination & TRACE_TERMINATION_LAST));
    
Exit:
    TRACE_PARSER__seek(parser, original_offset, SEEK_SET);
    return rc;
}

static int process_metadata_if_needed(trace_parser_t *parser, struct trace_record *record)
{
    if (NULL != get_buffer_context_by_pid(parser, record->pid)) {
        return 0;
    }

    int rc = process_metadata(parser, record);
    return rc;
}

static bool_t match_record_dump_with_match_expression(struct trace_record_matcher_spec_s *matcher, struct trace_record *record, struct trace_parser_buffer_context *buffer_context)
{
    struct trace_record_buffer_dump *buffer_dump = &record->u.buffer_chunk;
    if (matcher->type == TRACE_MATCHER_TRUE) {
        return TRUE;
    }

    if (matcher->type == TRACE_MATCHER_FALSE) {
        return FALSE;
    }

    
    if (matcher->type == TRACE_MATCHER_NOT) {
        return !match_record_dump_with_match_expression(matcher->u.unary_operator_parameters.param, record, buffer_context);
    }

    if (matcher->type == TRACE_MATCHER_OR) {
        return (match_record_dump_with_match_expression(matcher->u.binary_operator_parameters.a, record, buffer_context) ||
                match_record_dump_with_match_expression(matcher->u.binary_operator_parameters.b, record, buffer_context));
    }

    if (matcher->type == TRACE_MATCHER_AND) {
        return (match_record_dump_with_match_expression(matcher->u.binary_operator_parameters.a, record, buffer_context) &&
                match_record_dump_with_match_expression(matcher->u.binary_operator_parameters.b, record, buffer_context));
    }

    if (matcher->type == TRACE_MATCHER_PID) {
        return record->pid == matcher->u.pid;
    }

    if (matcher->type == TRACE_MATCHER_TID) {
        return TRUE;
    }

    if (matcher->type == TRACE_MATCHER_LOGID) {
        return TRUE;
    }

    if (matcher->type == TRACE_MATCHER_SEVERITY) {
        return (buffer_dump->severity_type) & (1 << matcher->u.severity);
    }

    if (matcher->type == TRACE_MATCHER_TYPE) {
        return TRUE;
    }

    if (matcher->type == TRACE_MATCHER_FUNCTION) {
        return TRUE;
    }

    if (matcher->type == TRACE_MATCHER_LOG_PARAM_VALUE) {
        return TRUE;
    }

    if (matcher->type == TRACE_MATCHER_LOG_NAMED_PARAM_VALUE) {
        return TRUE;
    }

    if (matcher->type == TRACE_MATCHER_TIMERANGE) {
        return TRUE;
    }

    if (matcher->type == TRACE_MATCHER_PROCESS_NAME && buffer_context) {
        if (strcmp(matcher->u.process_name, buffer_context->name) == 0) {
            return TRUE;
        } else {
            return FALSE;
        }
    }

    return TRUE;
}

static bool_t match_severity_with_match_expression(struct trace_record_matcher_spec_s *matcher, enum trace_severity severity)
{
    if (matcher->type == TRACE_MATCHER_TRUE) {
        return TRUE;
    }

    if (matcher->type == TRACE_MATCHER_FALSE) {
        return FALSE;
    }

    
    if (matcher->type == TRACE_MATCHER_NOT) {
        return !match_severity_with_match_expression(matcher->u.unary_operator_parameters.param, severity);
    }

    if (matcher->type == TRACE_MATCHER_OR) {
        return (match_severity_with_match_expression(matcher->u.binary_operator_parameters.a, severity) ||
                match_severity_with_match_expression(matcher->u.binary_operator_parameters.b, severity));
    }

    if (matcher->type == TRACE_MATCHER_AND) {
        return (match_severity_with_match_expression(matcher->u.binary_operator_parameters.a, severity) &&
                match_severity_with_match_expression(matcher->u.binary_operator_parameters.b, severity));
    }

    if (matcher->type == TRACE_MATCHER_SEVERITY) {
        return severity == matcher->u.severity;
    }
    
    return TRUE;
}

static int process_dump_header_record(trace_parser_t *parser, struct trace_record_matcher_spec_s *filter, struct trace_record *record)
{
    struct trace_record_dump_header *dump_header = &record->u.dump_header;
    struct trace_record_buffer_dump *buffer_chunk;
    struct trace_record tmp_record;
    unsigned int i = 0;
    int rc;
    rc = TRACE_PARSER__seek(parser, dump_header->first_chunk_offset, SEEK_SET);
    if (-1 == rc) {
        return -1;
    }

    long long current_offset = trace_file_current_offset(parser);
    long long end_offset = dump_header->total_dump_size + trace_file_current_offset(parser);
    parser->buffer_dump_context.end_offset = end_offset;
    parser->buffer_dump_context.previous_dump_offset = dump_header->prev_dump_offset;

    while (current_offset < end_offset) {
        if (i >= ARRAY_LENGTH(parser->buffer_dump_context.record_dump_contexts)) {
            return -1;
        }

        rc = read_next_record(parser, &tmp_record);
        if (0 != rc) {
            return -1;
        }

        if (tmp_record.rec_type != TRACE_REC_TYPE_BUFFER_CHUNK) {
            return -1;
        }

        buffer_chunk = &tmp_record.u.buffer_chunk;
            
        rc = process_metadata_if_needed(parser, &tmp_record);
        if (0 != rc) {
            return -1;
        }

        struct trace_parser_buffer_context *buffer_context = get_buffer_context_by_pid(parser, tmp_record.pid);
        if (NULL == buffer_context) {
            return -1;
        }
        
        if (!match_record_dump_with_match_expression(filter, &tmp_record, buffer_context)) {
            current_offset = TRACE_PARSER__seek(parser, buffer_chunk->records, SEEK_CUR);
            continue;
        }

        

        parser->buffer_dump_context.record_dump_contexts[i].start_offset = trace_file_current_offset(parser);
        parser->buffer_dump_context.record_dump_contexts[i].current_offset = parser->buffer_dump_context.record_dump_contexts[i].start_offset;
        parser->buffer_dump_context.record_dump_contexts[i].end_offset = parser->buffer_dump_context.record_dump_contexts[i].start_offset + buffer_chunk->records;
        current_offset = TRACE_PARSER__seek(parser, buffer_chunk->records, SEEK_CUR);
        if (-1 == current_offset) {
            return -1;
        }
        i++;
    }
    
    if (i) {
        current_offset = TRACE_PARSER__seek(parser, parser->buffer_dump_context.record_dump_contexts[0].start_offset, SEEK_SET);
    } else {
        current_offset = TRACE_PARSER__seek(parser, dump_header->first_chunk_offset - 1 + dump_header->total_dump_size, SEEK_SET);
    }
    
    if (current_offset == -1) {
        return -1;
    } else {
        parser->buffer_dump_context.num_chunks = i;
        return 0;
    }
}

static bool_t discard_record_on_nonseekable_stream(trace_parser_t *parser)
{
    if (parser->ignored_records_count) {
        parser->ignored_records_count--;
        return TRUE;
    } else {
        return FALSE;
    }
}

static bool_t params_have_type_name(struct trace_param_descriptor *param, const char *type_name)
{
    for (; param->flags != 0; param++) {
        if (!(param->flags & (TRACE_PARAM_FLAG_CSTR)) && param->type_name) {
            if (strcmp(param->type_name, type_name) == 0) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

static bool_t record_params_contain_value(struct trace_record *record, const char *param_name, struct trace_param_descriptor *param, unsigned long long value)
{
    unsigned char *pdata = record->u.typed.payload;
    unsigned long long param_value;
    for (; param->flags != 0; param++) {
        bool_t valid_value = FALSE;

        if (param->flags & TRACE_PARAM_FLAG_ENUM) {
            param_value = (unsigned long long) (*(unsigned int *)(pdata));
            pdata += sizeof(unsigned int);
            valid_value = TRUE;
        }
        
        if (param->flags & TRACE_PARAM_FLAG_NUM_8) {
            param_value = (unsigned long long) (*(unsigned char *)(pdata));
            pdata += sizeof(char);
            valid_value = TRUE;
        }
        if (param->flags & TRACE_PARAM_FLAG_NUM_16) {
            param_value = (unsigned long long) (*(unsigned short *)(pdata));
            pdata += sizeof(unsigned short);
            valid_value = TRUE;
        }
        if (param->flags & TRACE_PARAM_FLAG_NUM_32) {
            param_value = (unsigned long long) (*(unsigned int *)(pdata));
            pdata += sizeof(unsigned int);
            valid_value = TRUE;
        }
        if (param->flags & TRACE_PARAM_FLAG_NUM_64) {
            param_value = *((unsigned long long *) (pdata));
            pdata += sizeof(unsigned long long);
            valid_value = TRUE;
        }
        
        if (param->flags & TRACE_PARAM_FLAG_VARRAY) {
            while (1) {
                unsigned char sl = (*(unsigned char *)pdata);
                unsigned char len = sl & 0x7f;
                unsigned char continuation = sl & 0x80;
                
                pdata += sizeof(len) + len;
                if (!continuation) {
                    break;
                }
            }

            continue;
        }
        

        if (param_name) {
            if (!(param->param_name)) {
                continue;
            }
        }

        if (valid_value && value == param_value) {
            return TRUE;
        }        
    }

    return FALSE;
}

static bool_t match_record_with_match_expression(struct trace_record_matcher_spec_s *matcher, struct trace_parser_buffer_context *buffer, struct trace_record *record);
static bool_t match_record_with_match_expression(struct trace_record_matcher_spec_s *matcher, struct trace_parser_buffer_context *buffer, struct trace_record *record)
{
    unsigned int metadata_index = record->u.typed.log_id;
    if (metadata_index >= buffer->metadata->log_descriptor_count) {
        return FALSE;
    }

    struct trace_log_descriptor *log_desc = &buffer->descriptors[metadata_index];

    switch (matcher->type) {
    case TRACE_MATCHER_TRUE:
        return TRUE;
        break;
    case TRACE_MATCHER_FALSE:
        return FALSE;
        break;
    case TRACE_MATCHER_NOT:
        return !match_record_with_match_expression(matcher->u.unary_operator_parameters.param, buffer, record);
        break;
    case TRACE_MATCHER_OR:
        return (match_record_with_match_expression(matcher->u.binary_operator_parameters.a, buffer, record) ||
                match_record_with_match_expression(matcher->u.binary_operator_parameters.b, buffer, record));
        break;
    case TRACE_MATCHER_AND:
        return (match_record_with_match_expression(matcher->u.binary_operator_parameters.a, buffer, record) &&
                match_record_with_match_expression(matcher->u.binary_operator_parameters.b, buffer, record));
        break;
    case TRACE_MATCHER_PID:
        return record->pid == matcher->u.pid;
        break;
    case TRACE_MATCHER_TID:
        return record->tid == matcher->u.tid;
        break;
    case TRACE_MATCHER_LOGID:
        return record->u.typed.log_id == matcher->u.log_id;
        break;
    case TRACE_MATCHER_SEVERITY:
        return record->severity == matcher->u.severity;
        break;
    case TRACE_MATCHER_TYPE:
        return params_have_type_name(log_desc->params, matcher->u.type_name);
        break;
    case TRACE_MATCHER_FUNCTION:
        if ((log_desc->kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY) ||
            (log_desc->kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE)) {
            if (strcmp(log_desc->params->const_str, matcher->u.function_name) == 0) {
                return TRUE;
            } else {
                return FALSE;
            }
        }
        break;
        
    case TRACE_MATCHER_LOG_PARAM_VALUE:
        return record_params_contain_value(record, NULL, log_desc->params, matcher->u.param_value);
        break;
    case TRACE_MATCHER_LOG_NAMED_PARAM_VALUE:
        return record_params_contain_value(record, matcher->u.named_param_value.param_name, log_desc->params, matcher->u.named_param_value.param_value);
        break;
    case TRACE_MATCHER_TIMERANGE:
        return ((record->ts < matcher->u.time_range.end) && (record->ts > matcher->u.time_range.start));
        break;
    case TRACE_MATCHER_PROCESS_NAME:
        if (strcmp(matcher->u.process_name, buffer->name) == 0) {
            return TRUE;
        } else {
            return FALSE;
        }
        break;

    default:
        return FALSE;
        
    }

    return FALSE;
}



static bool_t should_filter_record(struct trace_record_matcher_spec_s *filter, struct trace_parser_buffer_context *buffer, struct trace_record *record)
{
    return !match_record_with_match_expression(filter, buffer, record);
}

static int process_single_record(trace_parser_t *parser, struct trace_record_matcher_spec_s *filter, struct trace_record *record, int *complete_typed_record_found,
                                 bool_t accumulate_forward, trace_parser_event_handler_t handler, void *arg)
{
    int rc = 0;
    struct trace_parser_buffer_context *buffer;
    struct trace_record *complete_record;
    struct parser_complete_typed_record complete_rec;
    switch (record->rec_type) {
    case TRACE_REC_TYPE_UNKNOWN:
        rc = -1;
        break;
    case TRACE_REC_TYPE_TYPED:
        if (discard_record_on_nonseekable_stream(parser)) {
            rc = 0;
            break;
        }

        rc = process_typed_record(parser, accumulate_forward, record, &complete_record, &buffer);
        if (0 == rc) {
            complete_rec.buffer = buffer;
            complete_rec.record = complete_record;
            if (!should_filter_record(filter, buffer, complete_record)) {
                handler(parser, TRACE_PARSER_COMPLETE_TYPED_RECORD_PROCESSED, &complete_rec, arg);
                *complete_typed_record_found = 1;
            }
            free_accumulator(parser, complete_record);
        }

        rc = 0;
        break;
    case TRACE_REC_TYPE_FILE_HEADER:
        strncpy(parser->file_info.machine_id, (char * ) record->u.file_header.machine_id, sizeof(parser->file_info.machine_id));
        parser->file_info.boot_time = record->u.file_header.boot_time;
        break;
    case TRACE_REC_TYPE_METADATA_HEADER:
        rc = metadata_info_started(parser, record);
        break;
    case TRACE_REC_TYPE_METADATA_PAYLOAD:
        rc = accumulate_metadata(parser, record);
        break;
    case TRACE_REC_TYPE_DUMP_HEADER:
        process_dump_header_record(parser, filter, record);
        break;
    case TRACE_REC_TYPE_BUFFER_CHUNK:
        process_buffer_chunk_record(parser, record);
        break;
    case TRACE_REC_TYPE_END_OF_FILE:
        rc = -1;
        break;
    default:
        rc = -1;
    }

    return rc;
}

static bool_t inside_record_dump(trace_parser_t *parser)
{
    unsigned int i;
    for (i = 0; i < parser->buffer_dump_context.num_chunks; i++) {
        if (parser->buffer_dump_context.record_dump_contexts[i].current_offset < parser->buffer_dump_context.record_dump_contexts[i].end_offset) {
            return TRUE;
        }
    }

    return FALSE;
}


static int read_smallest_ts_record(trace_parser_t *parser, struct trace_record *record)
{
    struct trace_record tmp_record;
    memset(&tmp_record, 0, sizeof(tmp_record));
    unsigned int i;
    unsigned long long min_ts = MAX_ULLONG;
    int rc;
    unsigned int index_of_minimal_chunk = 0;

    for (i = 0; i < parser->buffer_dump_context.num_chunks; i++) {
        if (parser->buffer_dump_context.record_dump_contexts[i].current_offset >= parser->buffer_dump_context.record_dump_contexts[i].end_offset) {
            continue;
        }

        rc = read_record_at_offset(parser, parser->buffer_dump_context.record_dump_contexts[i].current_offset, &tmp_record);
        if (0 != rc) {
            return -1;
        }
        
        if (tmp_record.ts < min_ts) {
            min_ts = tmp_record.ts;
            index_of_minimal_chunk = i;
            memcpy(record, &tmp_record, sizeof(*record));
        }
    }

    if (min_ts == MAX_ULLONG) {
        memset(record, 0, sizeof(*record));
    } else {
        parser->buffer_dump_context.record_dump_contexts[index_of_minimal_chunk].current_offset++;
    }

    return 0;
}

static int get_biggest_ts_record_chunk_index(trace_parser_t *parser)
{
    struct trace_record tmp_record;
    memset(&tmp_record, 0, sizeof(tmp_record));
    unsigned int i;
    unsigned long long max_ts = 0;
    int rc = -1;
    unsigned int index_of_maximal_chunk = 0;

    for (i = 0; i < parser->buffer_dump_context.num_chunks; i++) {
        if (parser->buffer_dump_context.record_dump_contexts[i].current_offset < parser->buffer_dump_context.record_dump_contexts[i].start_offset) {
            continue;
        }

        rc =  read_record_at_offset(parser, parser->buffer_dump_context.record_dump_contexts[i].current_offset - 1, &tmp_record);
        
        if (0 != rc) {
            return -1;
        }
        
        if (tmp_record.ts > max_ts) {
            max_ts = tmp_record.ts;
            index_of_maximal_chunk = i;
        }
    }

    if (max_ts == 0) {
        return -1;
    } else {
        return index_of_maximal_chunk;
    }
}


static int process_next_record_from_file(trace_parser_t *parser, struct trace_record_matcher_spec_s *filter, trace_parser_event_handler_t event_handler, void *arg)
{
    struct trace_record record;

    int complete_typed_record_processed = 0;
    int rc;
    while (TRUE) {
        if (inside_record_dump(parser)) {
            rc = read_smallest_ts_record(parser, &record);
            if (record.ts == 0) {
                ASSERT(-1 != TRACE_PARSER__seek(parser, parser->buffer_dump_context.end_offset, SEEK_SET));
                continue;
            }
        } else {
            rc = read_next_record(parser, &record);
        }

        
        if (0 != rc) {
            return -1;
        }

        rc = process_single_record(parser, filter, &record, &complete_typed_record_processed, TRUE, event_handler, arg);
        if (0 != rc) {
            return -1;
        }
        
        if (complete_typed_record_processed) {
            return 0;
        }
    }
}

static void dumper_event_handler(trace_parser_t *parser, enum trace_parser_event_e event, void *event_data, void __attribute__((unused)) *arg)
{
    if (event != TRACE_PARSER_COMPLETE_TYPED_RECORD_PROCESSED) {
        return;
    }

    char formatted_record[2048];
    struct parser_complete_typed_record *complete_typed_record = (struct parser_complete_typed_record *) event_data;
    TRACE_PARSER__format_typed_record(parser, complete_typed_record->buffer, complete_typed_record->record, formatted_record, sizeof(formatted_record));
    printf("%s\n", formatted_record);
}

int TRACE_PARSER__dump(trace_parser_t *parser)
{
    struct dump_context_s dump_context;
    if (parser->stream_type != TRACE_INPUT_STREAM_TYPE_SEEKABLE_FILE) {
        return -1;
    }
    
    while (1) {
        int rc = process_next_record_from_file(parser, &parser->record_filter, dumper_event_handler, &dump_context);
        if (0 != rc) {
            return -1;
        }
    }

    return 0;
}

static int restore_parsing_buffer_dump_context(trace_parser_t *parser, struct buffer_dump_context_s *dump_context)
{
    memcpy(&parser->buffer_dump_context, dump_context, sizeof(parser->buffer_dump_context));
    return TRACE_PARSER__seek(parser, parser->buffer_dump_context.file_offset, SEEK_SET);
}

int TRACE_PARSER__process_all_metadata(trace_parser_t *parser)
{
    struct dump_context_s dump_context;
    struct buffer_dump_context_s orig_dump_context;
    if (parser->stream_type != TRACE_INPUT_STREAM_TYPE_SEEKABLE_FILE) {
        return -1;
    }

    memcpy(&orig_dump_context, &parser->buffer_dump_context, sizeof(orig_dump_context));
    struct trace_record_matcher_spec_s matcher;
    matcher.type = TRACE_MATCHER_FALSE;
    
    while (1) {
        int rc = process_next_record_from_file(parser, &matcher, dumper_event_handler, &dump_context);
        if (0 != rc) {
            break;
        }
    }

    restore_parsing_buffer_dump_context(parser, &orig_dump_context);
    return 0;
}

static void format_record_event_handler(trace_parser_t *parser, enum trace_parser_event_e event, void *event_data, void *arg)
{
    if (event != TRACE_PARSER_COMPLETE_TYPED_RECORD_PROCESSED) {
        return;
    }

    struct parser_complete_typed_record *complete_typed_record = (struct parser_complete_typed_record *) event_data;
    struct dump_context_s *dump_context = (struct dump_context_s *) arg;
    TRACE_PARSER__format_typed_record(parser, complete_typed_record->buffer, complete_typed_record->record, dump_context->formatted_record, sizeof(dump_context->formatted_record));

    return;
}

int TRACE_PARSER__process_next_from_memory(trace_parser_t *parser, struct trace_record *rec, char *formatted_record, unsigned int formatted_record_size, unsigned int *record_formatted)
{
    if (parser->stream_type != TRACE_INPUT_STREAM_TYPE_NONSEEKABLE) {
        return -1;
    }
    struct dump_context_s dump_context;
    memset(&dump_context, 0, sizeof(dump_context));
    int complete_record_processed;
    int rc = process_single_record(parser, &parser->record_filter, rec, &complete_record_processed, TRUE, format_record_event_handler, &dump_context);
    if (strlen(dump_context.formatted_record)) {
        strncpy(formatted_record, dump_context.formatted_record, formatted_record_size);
        *record_formatted = 1;
    } else {
        *record_formatted = 0;
    }
    
    return rc;
}

int TRACE_PARSER__process_next_record_from_file(trace_parser_t *parser)
{
    if (cached_file__is_open(&parser->file_info.file_handle) < 0) {
        return -1;
    }

    return process_next_record_from_file(parser, &parser->record_filter, parser->event_handler, parser->arg);
}

static int process_dump_header_record_from_end(trace_parser_t *parser, struct trace_record_matcher_spec_s *filter, struct trace_record *record)
{
    int rc;
    rc = process_dump_header_record(parser, filter, record);
    if (0 != rc) {
        return -1;
    }

    unsigned int i;
    for (i = 0; i < parser->buffer_dump_context.num_chunks; i++) {
        parser->buffer_dump_context.record_dump_contexts[i].current_offset = parser->buffer_dump_context.record_dump_contexts[i].end_offset;
    }

    return 0;
}

static int process_previous_record_from_file(trace_parser_t *parser, struct trace_record_matcher_spec_s *filter, trace_parser_event_handler_t event_handler, void *arg)
{
    struct trace_record record;
    int rc;
    int chunk_index;
    bool_t complete_typed_record_found = FALSE;

    while (TRUE) {
        chunk_index = get_biggest_ts_record_chunk_index(parser);
        // TODO: Refactor this
        if (chunk_index < 0) {
            if (parser->buffer_dump_context.previous_dump_offset == 0) {
                return -1;
            }
            
            read_record_at_offset(parser, parser->buffer_dump_context.previous_dump_offset, &record);
            if (record.rec_type != TRACE_REC_TYPE_DUMP_HEADER) {
                return -1;
            }

            rc = process_dump_header_record_from_end(parser, filter, &record);
            if (0 != rc) {
                return -1;
            }

            chunk_index = get_biggest_ts_record_chunk_index(parser);
            if (chunk_index < 0) {
                return -1;
            }
        } 

        rc = read_record_at_offset(parser, parser->buffer_dump_context.record_dump_contexts[chunk_index].current_offset, &record);
        if (0 != rc) {
            return -1;
        }


        // TODO: Unify all of this under process_single_record()
        if (record.rec_type == TRACE_REC_TYPE_END_OF_FILE || record.rec_type == TRACE_REC_TYPE_DUMP_HEADER || record.rec_type == TRACE_REC_TYPE_BUFFER_CHUNK) {
            parser->buffer_dump_context.record_dump_contexts[chunk_index].current_offset--;
            continue;
        }
        rc = process_single_record(parser, filter, &record, &complete_typed_record_found, FALSE, event_handler, arg);
        if (0 == rc && complete_typed_record_found) {
            parser->buffer_dump_context.record_dump_contexts[chunk_index].current_offset--;
            break;
        } else if (0 != rc) {
            return -1;
        }

        parser->buffer_dump_context.record_dump_contexts[chunk_index].current_offset--;
    }

    return rc;
}

int TRACE_PARSER__process_previous_record_from_file(trace_parser_t *parser)
{
    if (cached_file__is_open(&parser->file_info.file_handle) < 0) {
        return -1;
    }

    int rc = process_previous_record_from_file(parser, &parser->record_filter, parser->event_handler, parser->arg);
    return rc;
}


static void count_function_entries(trace_parser_t __attribute__((unused)) *parser, enum trace_parser_event_e event, void __attribute__((unused)) *event_data, void __attribute__((unused)) *arg)
{
    if (event != TRACE_PARSER_COMPLETE_TYPED_RECORD_PROCESSED) {
        return;
    }
    
    struct parser_complete_typed_record *complete_typed_record = (struct parser_complete_typed_record *) event_data;
    struct trace_log_descriptor *log_desc;
    struct function_stats *stats = (struct function_stats *) arg;
    struct function_entry_count *s = NULL;

    if (!(complete_typed_record->record->termination & TRACE_TERMINATION_FIRST)) {
        if (stats->inside_record_entry) {
            stats->function_byte_count += sizeof(*complete_typed_record->record);
            if (complete_typed_record->record->termination & TRACE_TERMINATION_LAST) {
                stats->inside_record_entry = 0;
            }
        } else {
            stats->debug_byte_count += sizeof(*complete_typed_record->record);
        }
        return;
    }
    
    unsigned int metadata_index = complete_typed_record->record->u.typed.log_id;
    if (metadata_index >= complete_typed_record->buffer->metadata->log_descriptor_count) {
        return;
    }

    log_desc = &complete_typed_record->buffer->descriptors[metadata_index];
    if (log_desc->params->flags & TRACE_PARAM_FLAG_ENTER) {
        stats->function_byte_count += sizeof(*complete_typed_record->record);
        stats->inside_record_entry = 1;
        int rc = find_function_stats(stats, log_desc->params->const_str, &s);
        if (rc < 0) {
            strncpy(stats->functions[stats->count].name, log_desc->params->const_str, sizeof(stats->functions[stats->count]));
            stats->functions[stats->count].entry_count = 1;
            stats->functions[stats->count].leave_count = 0;
            stats->count++;
        } else {
            s->entry_count++;
        }
    } else if (log_desc->params->flags & TRACE_PARAM_FLAG_LEAVE) {
        stats->function_byte_count += sizeof(*complete_typed_record->record);
        stats->inside_record_entry = 1;
        int rc = find_function_stats(stats, log_desc->params->const_str, &s);
        if (rc < 0) {
            strncpy(stats->functions[stats->count].name, log_desc->params->const_str, sizeof(stats->functions[stats->count]));
            stats->functions[stats->count].leave_count = 1;
            stats->functions[stats->count].entry_count = 0;
            stats->count++;
        } else {
            s->leave_count++;
        }
    }
    else {
        stats->debug_byte_count += sizeof(*complete_typed_record->record);
    }
    
    return;
}

int TRACE_PARSER__dump_statistics(trace_parser_t *parser)
{
    if (parser->stream_type != TRACE_INPUT_STREAM_TYPE_SEEKABLE_FILE) {
        return -1;
    }
    
    struct function_stats *stats = malloc(sizeof(struct function_stats));
    unsigned int count = 0;
    while (1) {
        int rc = process_next_record_from_file(parser, &parser->record_filter, count_function_entries, (void *) stats);
        count++;
        if (0 != rc) {
            dump_stats(stats);
            free(stats);
            return 0;
        }
    }
}

static long long trace_end_offset(trace_parser_t *parser)
{
    long long orig_offset = trace_file_current_offset(parser);
    if (orig_offset == -1) {
        return -1;
    }

    long long end_offset = TRACE_PARSER__seek(parser, 0, SEEK_END);
    TRACE_PARSER__seek(parser, orig_offset, SEEK_SET);
    return end_offset;
}


int TRACE_PARSER__from_file(trace_parser_t *parser, const char *filename, trace_parser_event_handler_t event_handler, void *arg)
{
    int rc;

    trace_parser_init(parser, event_handler, arg, TRACE_INPUT_STREAM_TYPE_SEEKABLE_FILE);
    rc = cached_file__open(&parser->file_info.file_handle, filename, O_RDONLY);
    if (rc < 0) {
        return -1;
    }

    struct trace_record file_header;

    rc = read_file_header(parser, &file_header);
    if (0 != rc) {
        cached_file__close(&parser->file_info.file_handle);
        return -1;
    }

    strncpy(parser->file_info.filename, filename, sizeof(parser->file_info.filename));    
    strncpy(parser->file_info.machine_id, (char * ) file_header.u.file_header.machine_id, sizeof(parser->file_info.machine_id));
    parser->file_info.boot_time = file_header.u.file_header.boot_time;
    return 0;
}

void TRACE_PARSER__from_external_stream(trace_parser_t *parser, trace_parser_event_handler_t event_handler, void *arg)
{
    trace_parser_init(parser, event_handler, arg, TRACE_INPUT_STREAM_TYPE_NONSEEKABLE);
}

void TRACE_PARSER__fini(trace_parser_t *parser)
{
    if (cached_file__is_open(&parser->file_info.file_handle) < 0) {
        return;
    }

    int i;
    struct trace_parser_buffer_context *ptr;

    for (i = 0; i < BufferParseContextList__element_count(&parser->buffer_contexts); i++) {
        BufferParseContextList__get_element_ptr(&parser->buffer_contexts, i, &ptr);
        free(ptr->metadata);
    }
}

long long TRACE_PARSER__seek(trace_parser_t *parser, long long offset, int whence)
{
    long long absolute_offset = offset * sizeof(struct trace_record);
    if (parser->stream_type == TRACE_INPUT_STREAM_TYPE_NONSEEKABLE) {
        return -1;
    }
    
    if (cached_file__is_open(&parser->file_info.file_handle) < 0) {
        return -1;
    }

    off_t new_offset = cached_file__lseek(&parser->file_info.file_handle, absolute_offset, whence);
    if (new_offset == -1) {
        return -1;
    } else {
        parser->buffer_dump_context.file_offset = new_offset / sizeof(struct trace_record);
        return parser->buffer_dump_context.file_offset;
    }
}

long long find_record_by_ts(trace_parser_t *parser, unsigned long long ts, long long min, long long max, unsigned long long *found_ts)
{
    struct trace_record record;
    memset(&record, 0, sizeof(record));

    record.rec_type = TRACE_REC_TYPE_UNKNOWN;
    long long mid = 0;
    *found_ts = 0;
    while (max >= min)
    {
        /* calculate the midpoint for roughly equal partition */
        mid = (min + max) / 2;

        record.rec_type = TRACE_REC_TYPE_UNKNOWN;
        int rc = read_record_at_offset(parser, mid, &record);
        if (0 != rc) {
            return -1;
        }

        if  (record.ts < ts)
            min = mid + 1;
        else if (record.ts > ts)
            max = mid - 1;
        else {
            break;
        }
    }

    *found_ts = record.ts;
    return mid;
}

int get_previous_record_by_type_from_current_offset(trace_parser_t *parser, struct trace_record *record, enum trace_rec_type record_type)
{
    int rc;
    long long original_offset = trace_file_current_offset(parser);
    if (original_offset == -1) {
        return -1;
    }
    
    while (TRUE) {
        rc = TRACE_PARSER__seek(parser, -1, SEEK_CUR);
        if (-1 == rc) {
            rc = -1;
            break;
        }

        rc = read_next_record(parser, record);
        if (rc < 0) {
            rc = -1;
            break;
        }

        if (record->rec_type == record_type) {
            rc = 0;
            break;
        }
        
        rc = TRACE_PARSER__seek(parser, -1, SEEK_CUR);
        if (rc == -1) {
            rc = -1;
            break;
        }
    }
        
    TRACE_PARSER__seek(parser, original_offset, SEEK_SET);
    return rc;
}

int get_next_record_by_type_from_current_offset(trace_parser_t *parser, struct trace_record *record, enum trace_rec_type record_type)
{
    int rc;
    long long original_offset = trace_file_current_offset(parser);
    if (original_offset == -1) {
        return -1;
    }
    
    while (TRUE) {
        rc = read_next_record(parser, record);
        if (rc < 0) {
            rc = -1;
            break;
        }

        if (record->rec_type == record_type) {
            rc = 0;
            break;
        }
    }
        
    TRACE_PARSER__seek(parser, original_offset, SEEK_SET);
    return rc;
}


static void set_record_dumps_ts(trace_parser_t *parser, unsigned long long ts)
{
    unsigned int i;
    for (i = 0; i < parser->buffer_dump_context.num_chunks; i++) {
        unsigned long long found_ts;
        long long new_offset = find_record_by_ts(parser, ts, parser->buffer_dump_context.record_dump_contexts[i].start_offset, parser->buffer_dump_context.record_dump_contexts[i].end_offset - 1, &found_ts);
        parser->buffer_dump_context.record_dump_contexts[i].current_offset = new_offset;
    }
}

int set_buffer_dump_context_from_ts(trace_parser_t *parser, struct trace_record_matcher_spec_s *filter, unsigned long long ts, long long new_offset)
{
    struct trace_record record;
    memset(&record, 0, sizeof(record));
    long long rc;
    rc = TRACE_PARSER__seek(parser, new_offset, SEEK_SET);
    if (-1 == rc) {
        return -1;
    }

    rc = get_previous_record_by_type_from_current_offset(parser, &record, TRACE_REC_TYPE_DUMP_HEADER);
    if (0 != rc) {
        rc = get_next_record_by_type_from_current_offset(parser, &record, TRACE_REC_TYPE_DUMP_HEADER);
    }
    
    if (0 != rc) {
        return -1;
    }

    rc = process_dump_header_record(parser, filter, &record);
    if (0 != rc) {
        return -1;
    }

    set_record_dumps_ts(parser, ts);
    return 0;
}

unsigned long long TRACE_PARSER__seek_to_time(trace_parser_t *parser, unsigned long long ts, int *error_occurred)
{
    unsigned long long new_ts = 0;
    long long orig_offset = trace_file_current_offset(parser);
    long long new_offset = find_record_by_ts(parser, ts, 0, trace_end_offset(parser) - 1, &new_ts);
    if (-1 == new_offset) {
        TRACE_PARSER__seek(parser, orig_offset, SEEK_SET);
        *error_occurred = 1;
        return -1;
    }
    int rc = set_buffer_dump_context_from_ts(parser, &parser->record_filter, ts, new_offset);
    if (0 != rc) {
        *error_occurred = 1;
        return -1;
    }

    rc = TRACE_PARSER__find_next_record_by_expression(parser, &parser->record_filter);
    if (0 != rc) {
        rc = TRACE_PARSER__find_previous_record_by_expression(parser, &parser->record_filter);
    }

    if (0 != rc) {
        *error_occurred = 1;
    } else {
        *error_occurred = 0;
    }
    return new_ts;
}


unsigned long long get_max_tsc_offset(trace_parser_t *parser)
{
    off_t current_offset = TRACE_PARSER__seek(parser, 0, SEEK_CUR);
    struct trace_record record;
    unsigned long long max_tsc_offset = 0;
    int rc;
    cached_file__lseek(&parser->file_info.file_handle, 0, SEEK_END);
    while (1) {
        TRACE_PARSER__seek(parser, -1, SEEK_END);
        rc = read_next_record(parser, &record);
        if (rc < 0) {
            return 0;
        }

        if (record.termination & TRACE_TERMINATION_FIRST) {
            max_tsc_offset = TRACE_PARSER__seek(parser, 0, SEEK_CUR);
            break;
        }

        TRACE_PARSER__seek(parser, -1, SEEK_END);
    }

    TRACE_PARSER__seek(parser, current_offset, SEEK_CUR);
    return max_tsc_offset;
}

unsigned long long get_min_tsc_offset(trace_parser_t *parser)
{
    off_t current_offset = trace_file_current_offset(parser);
    struct trace_record record;
    unsigned long long min_tsc_offset = 0;
    int rc;
    
    TRACE_PARSER__seek(parser, 0, SEEK_SET);
    while (1) {
        rc = read_next_record(parser, &record);
        if (rc < 0) {
            return 0;
        }

        if (record.termination & TRACE_TERMINATION_FIRST) {
            min_tsc_offset = trace_file_current_offset(parser);
            break;
        }

    }

    TRACE_PARSER__seek(parser, current_offset, SEEK_CUR);
    return min_tsc_offset;
}


struct find_record_context_s {
    bool_t record_matched;
    struct trace_record_matcher_spec_s *expression;
};

typedef int (*record_getter_t)(trace_parser_t *parser, struct trace_record_matcher_spec_s *filter, trace_parser_event_handler_t event_handler, void *arg);

static void matcher_event_handler(trace_parser_t *parser, enum trace_parser_event_e event, void *event_data, void *arg)
{
    struct find_record_context_s *context = (struct find_record_context_s *) arg;
    if (event != TRACE_PARSER_COMPLETE_TYPED_RECORD_PROCESSED) {
        return;
    }

    struct parser_complete_typed_record *complete_typed_record = (struct parser_complete_typed_record *) event_data;
    context->record_matched = match_record_with_match_expression(context->expression, complete_typed_record->buffer, complete_typed_record->record);
    if (context->record_matched) {
        parser->event_handler(parser, TRACE_PARSER_MATCHED_RECORD, complete_typed_record, parser->arg);
    }    
}

static int find_record_by_expression(trace_parser_t *parser, record_getter_t record_getter, struct trace_record_matcher_spec_s *expression)
{
    struct find_record_context_s matcher_context;
    matcher_context.record_matched = FALSE;
    matcher_context.expression = expression;
    struct trace_record_matcher_spec_s filter_and_expression;
    filter_and_expression.type = TRACE_MATCHER_AND;
    filter_and_expression.u.binary_operator_parameters.a = &parser->record_filter;
    filter_and_expression.u.binary_operator_parameters.b = expression;
        
    while (1) {
        int rc = record_getter(parser, &filter_and_expression, matcher_event_handler, &matcher_context);
        if (0 != rc) {
            return -1;
        }

        if (matcher_context.record_matched) {
            return 0;
        }
    }
}

int TRACE_PARSER__find_next_record_by_expression(trace_parser_t *parser, struct trace_record_matcher_spec_s *expression)
{
    return find_record_by_expression(parser, process_next_record_from_file, expression);
}

int TRACE_PARSER__find_previous_record_by_expression(trace_parser_t *parser, struct trace_record_matcher_spec_s *expression)
{
    return find_record_by_expression(parser, process_previous_record_from_file, expression);
}

int TRACE_PARSER__matcher_spec_from_severity_mask(unsigned int severity_mask, struct trace_record_matcher_spec_s filter[], unsigned int filter_count)
{
    enum trace_severity current_severity = TRACE_SEV_FUNC_TRACE;
    unsigned int current_filter = 0;
    while (current_severity <= TRACE_SEV__MAX) {
        if ((1 << current_severity) & severity_mask) {
            if ((current_filter + 3) > filter_count) {
                return -1;
            }

            filter[current_filter].type = TRACE_MATCHER_OR;
            filter[current_filter].u.binary_operator_parameters.a = &filter[current_filter + 1];
            filter[current_filter].u.binary_operator_parameters.b = &filter[current_filter + 2];
            filter[current_filter + 1].type = TRACE_MATCHER_SEVERITY;
            filter[current_filter + 1].u.severity = current_severity;
            filter[current_filter + 2].type = TRACE_MATCHER_FALSE;
            current_filter += 2;
        }

        current_severity++;
    }

    return 0;
}
