#include "../trace_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>
#include "../list_template.h"
#include "../array_length.h"

typedef char trace_filename_t[0x100];
CREATE_LIST_PROTOTYPE(FilenameList, trace_filename_t)
CREATE_LIST_IMPLEMENTATION(FilenameList, trace_filename_t)

enum op_type_e {
    OP_TYPE_INVALID,
    OP_TYPE_DUMP_STATS,
    OP_TYPE_DUMP_FILE
};

struct trace_reader_conf {
    enum op_type_e op_type;
    unsigned int severity_mask;
    int tail;
    int no_color;
    int relative_ts;
    long long from_time;
    FilenameList files_to_process;
    struct trace_record_matcher_spec_s severity_filter[SEVERITY_FILTER_LEN];
};

static const char *usage = 
    "Usage: %s [params] [files]                                                                 \n"
    "                                                                                           \n"
    " -h, --help                 Display this help message                                      \n"
    " -d  --dump                 Dump contents of trace file                                    \n"
    " -n  --no-color             Disable colored output                                         \n"
    " -e  --dump-debug           Dump all debug entries                                         \n"
    " -f  --dump-functions       Dump all debug entries and fucntion calls                      \n"
    " -t  --time                 Dump all records beginning at timestamp (in usecs)             \n"
    " -r  --relative-timestamp   Print timestamps relative to boot time                         \n"
    "\n";

static const struct option longopts[] = {
    { "help", 0, 0, 'h'},
	{ "dump", 0, 0, 'd'},
	{ "no-color", 0, 0, 'n'},
    { "dump-debug", 0, 0, 'e'},
    { "dump-functions", 0, 0, 'f'},
    { "relative-timestamp", required_argument, 0, 't'},
	{ 0, 0, 0, 0}
};

static void print_usage(void)
{
    printf(usage, "simple_trace_reader");
}

static const char shortopts[] = "ft:hdnesr";

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
        case 't':
            conf->from_time = strtoll(optarg, NULL, 10);
            if (conf->from_time == LLONG_MIN || conf->from_time == LLONG_MAX) {
                fprintf(stderr, "Invalid time specification\n");
                print_usage();
                return -1;
            }
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

static void set_parser_params(struct trace_reader_conf *conf, trace_parser_t *parser)
{
    TRACE_PARSER__matcher_spec_from_severity_mask(conf->severity_mask, conf->severity_filter, ARRAY_LENGTH(conf->severity_filter));
    TRACE_PARSER__set_filter(parser, conf->severity_filter);
        
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
}

static int dump_all_files(struct trace_reader_conf *conf)
{
    trace_parser_t parser;
    int i;
    trace_filename_t filename;
    int error_occurred;
    for (i = 0; i < FilenameList__element_count(&conf->files_to_process); i++) {
        FilenameList__get_element(&conf->files_to_process, i, &filename);

        int rc = TRACE_PARSER__from_file(&parser, filename, read_event_handler, NULL);
        if (0 != rc) {
            fprintf(stderr, "Error opening file %s\n", filename);
            return -1;
        }

        set_parser_params(conf, &parser);
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
    trace_parser_t parser;
    int i;
    trace_filename_t filename;
    
    for (i = 0; i < FilenameList__element_count(&conf->files_to_process); i++) {
        FilenameList__get_element(&conf->files_to_process, i, &filename);

        int rc = TRACE_PARSER__from_file(&parser, filename, read_event_handler, NULL);
        if (0 != rc) {
            fprintf(stderr, "Error opening file %s\n", filename);
            return -1;
        }

        TRACE_PARSER__dump_statistics(&parser);
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
    case OP_TYPE_INVALID:
        fprintf(stderr, "simple_trace_reader: Must specify operation type (-s or -d)\n");
        print_usage();
    default:
        break;
    }
    
    return 0;
}
