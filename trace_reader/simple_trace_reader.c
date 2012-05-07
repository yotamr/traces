#include "trace_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>
#include "list_template.h"
#include "array_length.h"

typedef char trace_filename_t[0x100];
CREATE_LIST_PROTOTYPE(FilenameList, trace_filename_t)
CREATE_LIST_IMPLEMENTATION(FilenameList, trace_filename_t)

enum op_type_e {
    OP_TYPE_INVALID,
    OP_TYPE_DUMP_STATS,
    OP_TYPE_DUMP_FILE,
    OP_TYPE_DUMP_METADATA
};

struct trace_reader_conf {
    enum op_type_e op_type;
    const char *grep_expression;
    unsigned int severity_mask;
    int tail;
    int no_color;
    int show_field_names;
    int relative_ts;
    long long from_time;
    FilenameList files_to_process;
    struct trace_record_matcher_spec_s severity_filter[SEVERITY_FILTER_LEN];
    struct trace_record_matcher_spec_s grep_filter;
    struct trace_record_matcher_spec_s complete_filter;
};

static const char *usage = 
    "Usage: %s [params] [files]                                                                 \n"
    "                                                                                           \n"
    " -h, --help                 Display this help message                                      \n"
    " -d  --dump                 Dump contents of trace file                                    \n"
    " -n  --no-color             Disable colored output                                         \n"
    " -e  --dump-debug           Dump all debug entries                                         \n"
    " -f  --dump-functions       Dump all debug entries and fucntion calls                      \n"
    " -t  --time                 Dump all records beginning at timestamp, formatted according to trace output timestamps      \n"
    " -o  --show-field-names     Show field names for all trace records                         \n"
    " -r  --relative-timestamp   Print timestamps relative to boot time                         \n"
    " -i  --tail                 Display last records and wait for more data                    \n"
    " -g  --grep [expression]    Display records whose constant string matches the expression   \n"
    " -s  --print-stats          Print per-log occurrence count                                 \n"
    " -m  --dump-metadata        Dump metadata                                                  \n"
    "\n";

static const struct option longopts[] = {
    { "help", 0, 0, 'h'},
	{ "dump", 0, 0, 'd'},
	{ "no-color", 0, 0, 'n'},
    { "dump-debug", 0, 0, 'e'},
    { "dump-functions", 0, 0, 'f'},
    { "dump-metadata", 0, 0, 'm'},
    { "print-stats", 0, 0, 's'},
    { "show-field-name", 0, 0, 'o'},
    { "relative-timestamp", required_argument, 0, 't'},
    { "grep", required_argument, 0, 'g'},
    { "tail", 0, 0, 'i'},
	{ 0, 0, 0, 0}
};

static void print_usage(void)
{
    printf(usage, "simple_trace_reader");
}

static const char shortopts[] = "ig:moft:hdnesr";

#define SECOND (1000000000LL)
#define MINUTE (SECOND * 60LL)
#define HOUR (MINUTE * 60LL)
#define DAY (HOUR * 24LL)
#define YEAR (DAY * 365LL)

static long long timespec_to_nanosec(struct tm *time_spec)
{
    return (mktime(time_spec) * SECOND);
}

static long long maybe_process_nanosec(const char *str)
{
    if (*str == ':') {
        long long nano_seconds = strtoll(&str[1], NULL, 10);
        if (nano_seconds == LLONG_MAX || nano_seconds == LLONG_MIN) {
            return 0;
        } else {
            return nano_seconds;
        }
    } else {
        return 0;
    }
}

char *strptime(const char *s, const char *format, struct tm *tm);
static unsigned long long format_cmdline_time(const char *time_str)
{
    const char *format = "%a %b %d %T %Y";
    struct tm formatted_time;
    char *result = strptime(time_str, format, &formatted_time);
    if (NULL == result) {
        return LLONG_MIN;
    } else {
        long long from_time = timespec_to_nanosec(&formatted_time);
        from_time += maybe_process_nanosec(result);
        return from_time;
    }
}

static int parse_command_line(struct trace_reader_conf *conf, int argc, char **argv)
{
    int o;
    int longindex;
    conf->severity_mask = ((1 << TRACE_SEV_INFO) | (1 << TRACE_SEV_INFO) | (1 << TRACE_SEV_WARN) | (1 << TRACE_SEV_ERROR) | (1 << TRACE_SEV_FATAL));
    while ((o = getopt_long(argc, argv, shortopts, longopts, &longindex)) != EOF) {
		switch (o) {
		case 'h':
			print_usage();
			break;
		case 'd':
            conf->op_type = OP_TYPE_DUMP_FILE;
            break;
        case 'e':
            conf->severity_mask = conf->severity_mask | (1 << TRACE_SEV_DEBUG);
            break;
        case 'f':
            conf->severity_mask = conf->severity_mask | (1 << TRACE_SEV_FUNC_TRACE) | (1 << TRACE_SEV_DEBUG);
            break;
		case 's':
			conf->op_type = OP_TYPE_DUMP_STATS;
			break;
        case 'n':
            conf->no_color = 1;
            break;
        case 'r':
            conf->relative_ts = 1;
            break;
        case 'i':
            conf->tail = 1;
            break;
        case 't':
            conf->from_time = format_cmdline_time(optarg);
            if (conf->from_time == LLONG_MIN || conf->from_time == LLONG_MAX) {
                fprintf(stderr, "Invalid time specification\n");
                print_usage();
                return -1;
            }
            break;
        case 'm':
            conf->op_type = OP_TYPE_DUMP_METADATA;
            break;
        case 'g':
            conf->grep_expression = optarg;
            break;
        case 'o':
            conf->show_field_names = TRUE;
            break;
            
        case '?':
            print_usage();
            return -1;
            break;
        default:
            break;
        }
    }

    unsigned long filename_index = optind;
    while (filename_index < (unsigned int) argc) {
        trace_filename_t filename;
        strncpy(filename, argv[filename_index], sizeof(filename));
        FilenameList__add_element(&conf->files_to_process, &filename);
        filename_index++;
    }
    
    return 0;
}

void read_event_handler(struct trace_parser  __attribute__((unused)) *parser, enum trace_parser_event_e  __attribute__((unused)) event, void  __attribute__((unused)) *event_data, void  __attribute__((unused)) *arg)
{
    
}

static void set_parser_filter(struct trace_reader_conf *conf, trace_parser_t *parser)
{
    TRACE_PARSER__matcher_spec_from_severity_mask(conf->severity_mask, conf->severity_filter, ARRAY_LENGTH(conf->severity_filter));
    struct trace_record_matcher_spec_s *filter = conf->severity_filter;
    if (conf->grep_expression) {
        conf->grep_filter.type = TRACE_MATCHER_CONST_SUBSTRING;
        strncpy(conf->grep_filter.u.const_string, conf->grep_expression, sizeof(conf->grep_filter.u.const_string));

        conf->complete_filter.type = TRACE_MATCHER_AND;
        conf->complete_filter.u.binary_operator_parameters.a = &conf->grep_filter;
        conf->complete_filter.u.binary_operator_parameters.b = conf->severity_filter;
        filter = &conf->complete_filter;
    }
    
    TRACE_PARSER__set_filter(parser, filter);
    
}
static void set_parser_params(struct trace_reader_conf *conf, trace_parser_t *parser)
{

    set_parser_filter(conf, parser);
        
    if (conf->no_color) {
        TRACE_PARSER__set_color(parser, 0);
    } else {
        TRACE_PARSER__set_color(parser, 1);
    }

    if (conf->severity_mask & (1 << TRACE_SEV_FUNC_TRACE)) {
        TRACE_PARSER__set_indent(parser, TRUE);
    } else {
        TRACE_PARSER__set_indent(parser, FALSE);
    }

    if (conf->relative_ts) {
        TRACE_PARSER__set_relative_ts(parser, 1);
    } else {
        TRACE_PARSER__set_relative_ts(parser, 0);
    }

    if (conf->show_field_names) {
        TRACE_PARSER__set_show_field_names(parser, 1);
    } else {
        TRACE_PARSER__set_show_field_names(parser, 0);
    }
}

static int dump_all_files(struct trace_reader_conf *conf)
{
    int i;
    trace_filename_t filename;
    int error_occurred;
    trace_parser_t parser;
    
    for (i = 0; i < FilenameList__element_count(&conf->files_to_process); i++) {
        FilenameList__get_element(&conf->files_to_process, i, &filename);
        int rc = TRACE_PARSER__from_file(&parser, conf->tail, filename, read_event_handler, NULL);
        if (0 != rc) {
            fprintf(stderr, "Error opening file %s\n", filename);
            return -1;
        }
        set_parser_params(conf, &parser);


        if (conf->tail) {
            TRACE_PARSER__seek_to_time(&parser, LLONG_MAX, &error_occurred);
            if (error_occurred) {
                fprintf(stderr, "Error seeking to end of file %llu\n", conf->from_time);
            }
        }
                
        if (conf->from_time) {
            TRACE_PARSER__seek_to_time(&parser, conf->from_time, &error_occurred);
            if (error_occurred) {
                fprintf(stderr, "Error seeking to time %llu\n", conf->from_time);
                return -1;
            }
        }
        
        TRACE_PARSER__dump(&parser);
        TRACE_PARSER__fini(&parser);
    }

    return 0;
}

static int dump_statistics_for_all_files(struct trace_reader_conf *conf)
{
    int i;
    trace_filename_t filename;
    trace_parser_t parser;
    
    for (i = 0; i < FilenameList__element_count(&conf->files_to_process); i++) {
        FilenameList__get_element(&conf->files_to_process, i, &filename);

        int rc = TRACE_PARSER__from_file(&parser, FALSE, filename, read_event_handler, NULL);
        set_parser_params(conf, &parser);

        if (0 != rc) {
            fprintf(stderr, "Error opening file %s\n", filename);
            return -1;
        }

        TRACE_PARSER__dump_statistics(&parser);
        TRACE_PARSER__fini(&parser);

    }

    return 0;
}

static int dump_metadata_for_files(struct trace_reader_conf *conf)
{
    int i;
    trace_filename_t filename;
    trace_parser_t parser;
    
    for (i = 0; i < FilenameList__element_count(&conf->files_to_process); i++) {
        FilenameList__get_element(&conf->files_to_process, i, &filename);

        int rc = TRACE_PARSER__from_file(&parser, FALSE, filename, read_event_handler, NULL);
        set_parser_params(conf, &parser);

        if (0 != rc) {
            fprintf(stderr, "Error opening file %s\n", filename);
            return -1;
        }

        TRACE_PARSER__dump_all_metadata(&parser);
        TRACE_PARSER__fini(&parser);

    }

    return 0;
}

int main(int argc, char **argv)
{
    struct trace_reader_conf conf;
    memset(&conf, 0, sizeof(conf));
    conf.severity_mask = ((1 << TRACE_SEV_DEBUG) | (1 << TRACE_SEV_FUNC_TRACE));
    int rc = parse_command_line(&conf, argc, argv);
    if (0 != rc) {
        return 1;
    }

    if (0 == FilenameList__element_count(&conf.files_to_process)) {
        fprintf(stderr, "simple_trace_reader: Must specify input files\n");
        return 1;
    }

    switch (conf.op_type) {
    case OP_TYPE_DUMP_STATS:
        return dump_statistics_for_all_files(&conf);
        return TRACE_PARSER__dump_statistics(NULL);
        break;
    case OP_TYPE_DUMP_FILE:
        return dump_all_files(&conf);
        break;
    case OP_TYPE_DUMP_METADATA:
        return dump_metadata_for_files(&conf);
        break;
    case OP_TYPE_INVALID:
        fprintf(stderr, "simple_trace_reader: Must specify operation type (-s or -d)\n");
        print_usage();
    default:
        break;
    }
    
    return 0;
}
