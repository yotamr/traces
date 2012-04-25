from ctypes import *
import sys
import time
from datetime import datetime
import _trace_parser_ctypes as _cparser_defs
from _trace_parser_ctypes import TRACE_MATCHER_TRUE, TRACE_MATCHER_OR, TRACE_MATCHER_AND, TRACE_MATCHER_NOT, TRACE_MATCHER_PID, \
     TRACE_MATCHER_TID, TRACE_MATCHER_TIMERANGE, TRACE_MATCHER_LOGID, TRACE_MATCHER_SEVERITY, TRACE_MATCHER_FUNCTION, TRACE_MATCHER_LOG_PARAM_VALUE, \
     TRACE_MATCHER_TYPE, TRACE_MATCHER_LOG_NAMED_PARAM_VALUE, TRACE_MATCHER_PROCESS_NAME, TRACE_MATCHER_NESTING

from Bunch import Bunch
from _ast import UnaryOp, BoolOp, And, Or, Not, Compare, Eq, Name, Num, Call, Str, Lt
import ast

_traces_so = CDLL("./traces.so")

class UnableToOpenTraceFile(Exception):
    pass

SEEK_SET = 0
SEEK_CUR = 1
SEEK_END = 2

SECOND = 1000000000
MINUTE = SECOND * 60
HOUR = MINUTE * 60
DAY = HOUR * 24
YEAR = DAY * 365

TRACE_SEV_FUNC_TRACE = 1
TRACE_SEV_DEBUG = 2
TRACE_SEV_INFO = 3
TRACE_SEV_WARN = 4
TRACE_SEV_ERROR = 5
TRACE_SEV_FATAL = 6

def severity_name_to_severity_value(severity_name):
    full_severity_name = ''.join(('TRACE_SEV_', severity_name))
    if full_severity_name in globals():
        return globals()[full_severity_name]
    else:
        return False

def make_bound_handler(parser_obj):
    def event_handler(parser, event_type, event_data, arg):
        parser_obj.record_ready = False

        if event_type == _cparser_defs.TRACE_PARSER_FOUND_METADATA:
            if parser_obj._event_handler:
                parser_obj._event_handler('metadata_updated')
            return

        if event_type == _cparser_defs.TRACE_PARSER_OPERATION_IN_PROGRESS:
            if parser_obj._event_handler:
                progress_status = cast(c_void_p(event_data), POINTER(_cparser_defs.operation_progress_status_s))
                parser_obj._event_handler('operation_in_progress',
                                          records_processed = progress_status.contents.records_processed,
                                          current_offset = progress_status.contents.current_offset)
                return

        if event_type == _cparser_defs.TRACE_PARSER_UNKNOWN_RECORD_ENCOUNTERED:
            if parser_obj._event_handler:
                parser_obj._event_handler('unknown_record')
                return
            

        if event_type not in (_cparser_defs.TRACE_PARSER_COMPLETE_TYPED_RECORD_PROCESSED, _cparser_defs.TRACE_PARSER_MATCHED_RECORD):
            return


        complete_record_ptr = cast(c_void_p(event_data), POINTER(_cparser_defs.parser_complete_typed_record))
        formatted_record = create_string_buffer(1024 * 10)
        format_length = c_int()
        _traces_so.TRACE_PARSER__format_typed_record(parser, complete_record_ptr.contents.buffer, complete_record_ptr.contents.record, formatted_record, 1024 * 10, byref(format_length))
        parser_obj.record_ready = True
        parser_obj.formatted_record = formatted_record.value
        
        record_copy = _cparser_defs.trace_record()
        pointer(record_copy)[0] = complete_record_ptr.contents.record[0]
        parser_obj.raw_record = record_copy

    def safe_event_handler(parser, event_type, event_data, arg):
        try:
            event_handler(parser, event_type, event_data, arg)
        except KeyboardInterrupt:
            parser_obj._event_handler('interrupted')
            if parser_obj._event_handler:
                parser_obj._event_handler('interrupted')

    return safe_event_handler

class FilterParseError(Exception):
    pass

class TraceFilter(object):
    def __init__(self, parser, filter = None):
        self.filter = filter
        self.parser = parser
        self._struct_references = []
        
    def _handle_bool_op(self, bool_op):
        op_type_to_filter_type = {And : TRACE_MATCHER_AND,
                                  Or :  TRACE_MATCHER_OR}

        filter_type = op_type_to_filter_type[type(bool_op.op)]
        new_filter = _cparser_defs.trace_record_matcher_spec_s()
        new_filter.type = filter_type
        new_filter.u.binary_operator_parameters.a = pointer(self._parse_expression(bool_op.values[0]))
        new_filter.u.binary_operator_parameters.b = pointer(self._parse_expression(bool_op.values[1]))

        self._struct_references.append(new_filter.u.binary_operator_parameters.a)
        self._struct_references.append(new_filter.u.binary_operator_parameters.b)

        return new_filter

    def _get_expr_comparator_name(self, comparison):
        return comparison.left.id

    def _get_expr_comparator_value(self, comparison):
        if isinstance(comparison.comparators[0], Num):
            return comparison.comparators[0].n
        elif isinstance(comparison.comparators[0], Str):
            return comparison.comparators[0].s
        elif isinstance(comparison.comparators[0], Name):
            return comparison.comparators[0].id

    def _handle_unary_op(self, operation):
        if not isinstance(operation.op, Not):
            raise FilterParseError()
        
        new_filter = _cparser_defs.trace_record_matcher_spec_s()
        new_filter.type = TRACE_MATCHER_NOT
        self._struct_references.append(pointer(self._parse_expression(operation.operand)))
        new_filter.u.unary_operator_parameters.param = self._struct_references[-1]
        return new_filter

    def _is_time_filter(self, expression):
        if not len(expression.ops) == 2:
            return False
        
        if not (isinstance(expression.left, Str) and isinstance(expression.comparators[0], Name) and isinstance(expression.comparators[1], Str)):
            return False

        if expression.comparators[0].id != 'ts':
                return False

        return True

    def _handle_time_filter(self, expression):
        start_time = self.parser.partial_to_absolute_time(expression.left.s)
        if not start_time:
            return None

        end_time = self.parser.partial_to_absolute_time(expression.comparators[1].s)
        if not end_time:
            return None

        print start_time, end_time
        new_filter = _cparser_defs.trace_record_matcher_spec_s()
        new_filter.type = TRACE_MATCHER_TIMERANGE
        new_filter.u.time_range.start = start_time
        new_filter.u.time_range.end = end_time
        return new_filter
        
    def _handle_comparison(self, comparison):
        if isinstance(comparison.left, Str):
            if not self._is_time_filter(comparison):
                raise FilterParseError()

            new_filter = self._handle_time_filter(comparison)
            if not new_filter:
                raise FilterParseError()
            else:
                return new_filter
            
        if not isinstance(comparison.ops[0], Eq):
            raise FilterParseError()

        name = self._get_expr_comparator_name(comparison)
        value = self._get_expr_comparator_value(comparison)
        field_to_filter = {'pid' : TRACE_MATCHER_PID,
                           'tid' : TRACE_MATCHER_TID,
                           'log_id' : TRACE_MATCHER_LOGID,
                           'ts' : TRACE_MATCHER_TIMERANGE,
                           'nesting' : TRACE_MATCHER_NESTING,
                           'severity' : TRACE_MATCHER_SEVERITY}

        if not name in field_to_filter:
            raise FilterParseError()
        
        filter_type = field_to_filter[name]
        new_filter = _cparser_defs.trace_record_matcher_spec_s()
        new_filter.type = filter_type
        if filter_type == TRACE_MATCHER_PID:
            new_filter.u.pid = value
        elif filter_type == TRACE_MATCHER_NESTING:
            new_filter.u.nesting = value
        elif filter_type == TRACE_MATCHER_TID:
            new_filter.u.tid = value
        elif filter_type == TRACE_MATCHER_LOGID:
            new_filter.u.log_id = value
        elif filter_type == TRACE_MATCHER_SEVERITY:
            severity = severity_name_to_severity_value(value)
            if not severity:
                raise FilterParseError()
            
            new_filter.u.severity = severity

        return new_filter

    def _chain_and_matchers(self, matchers):
        root = _cparser_defs.trace_record_matcher_spec_s()
        current_matcher = root
        current_matcher.type = TRACE_MATCHER_AND
        for matcher in matchers:
            current_matcher.type = TRACE_MATCHER_AND
            current_matcher.u.binary_operator_parameters.a = pointer(matcher)
            self._struct_references.append(matcher)
            next_matcher = _cparser_defs.trace_record_matcher_spec_s()
            self._struct_references.append(next_matcher)
            next_matcher.type = TRACE_MATCHER_TRUE
            current_matcher.u.binary_operator_parameters.b = pointer(next_matcher)
            current_matcher = next_matcher

        true_matcher = _cparser_defs.trace_record_matcher_spec_s()
        true_matcher.type = TRACE_MATCHER_TRUE;
        current_matcher.u.binary_operator_parameters.b = pointer(true_matcher)
        self._struct_references.append(true_matcher)
        return root

    def _resolve_constant_value(self, value_name):
        if value_name not in self.parser.metadata['all_const_values']:
            return None
        else:
            return self.parser.metadata['all_const_values'][value_name]

    def _resolve_value(self, raw_value):
        if not isinstance(raw_value, (Num, Name)):
            raise FilterParseError()

        if isinstance(raw_value, Name):
            value = self._resolve_constant_value(raw_value.id)
            if value is None:
                raise FilterParseError()
        else:
            value = raw_value.n

        return value

    def _get_arg_matchers(self, args, keywords):
        value_matchers = []
        for arg in args:
            if not isinstance(arg, (Num, Name)):
                raise FilterParseError()

            
            value_matcher = _cparser_defs.trace_record_matcher_spec_s()
            value_matcher.type = TRACE_MATCHER_LOG_PARAM_VALUE
                
            value_matcher.u.param_value = self._resolve_value(arg)
            value_matchers.append(value_matcher)

        for keyword in keywords:
            name, value = keyword.arg, keyword.value
            field_matcher = _cparser_defs.trace_record_matcher_spec_s()
            field_matcher.type = TRACE_MATCHER_LOG_NAMED_PARAM_VALUE
            field_matcher.u.named_param_value.param_name = name;
            field_matcher.u.named_param_value.param_value = self._resolve_value(value)
            value_matchers.append(field_matcher)
            
            
        return value_matchers

    def _handle_log_filter(self, args, keywords):
        value_matchers = self._get_arg_matchers(args, keywords)
        return self._chain_and_matchers(value_matchers)
    
    def _handle_func_filter(self, func_name, args, keywords):
        func_filter = _cparser_defs.trace_record_matcher_spec_s()
        func_filter.type = TRACE_MATCHER_FUNCTION
        func_filter.u.function_name = func_name.strip()
        self._struct_references.append(func_filter)
        
        func_trace_severity_filter = _cparser_defs.trace_record_matcher_spec_s()
        func_trace_severity_filter.type = TRACE_MATCHER_SEVERITY
        func_trace_severity_filter.u.severity = TRACE_SEV_FUNC_TRACE
        self._struct_references.append(func_trace_severity_filter)

        severity_and_func = _cparser_defs.trace_record_matcher_spec_s()
        severity_and_func.type = TRACE_MATCHER_AND
        severity_and_func.u.binary_operator_parameters.a = pointer(func_filter)
        severity_and_func.u.binary_operator_parameters.b = pointer(func_trace_severity_filter)
        self._struct_references.append(severity_and_func)
        
        value_matchers = self._get_arg_matchers(args, keywords)
        
        if len(value_matchers):
            and_matchers = self._chain_and_matchers([severity_and_func] + value_matchers)
            return and_matchers
        else:
            return severity_and_func

    def _handle_procname_filter(self, process_name):
        process_filter = _cparser_defs.trace_record_matcher_spec_s()
        process_filter.type = TRACE_MATCHER_PROCESS_NAME
        process_filter.u.process_name = process_name
        self._struct_references.append(process_filter)
        return process_filter

    def _handle_typename(self, func_name, expression):
        type_name = expression.args[0].s
        type_filter = _cparser_defs.trace_record_matcher_spec_s()
        type_filter.type = TRACE_MATCHER_TYPE
        type_filter.u.type_name = type_name
        self._struct_references.append(type_filter)

        return type_filter

    def _handle_call(self, expression):
        func_name = expression.func.id
        if func_name == '_typename':
            return self._handle_typename(func_name, expression)
        elif func_name == '_call':
            return self._handle_func_filter(expression.args[0].s, expression.args[1:], expression.keywords)
        elif func_name == '_':
            return self._handle_log_filter(expression.args, expression.keywords)
        elif func_name == '_procname':
            return self._handle_procname_filter(expression.args[0].s)
        else:
            return self._handle_func_filter(func_name, expression.args, expression.keywords)

    def _parse_expression(self, expression):
        if not isinstance(expression, (UnaryOp, BoolOp, Compare, Call)):
            raise FilterParseError()

        if isinstance(expression, BoolOp):
            return self._handle_bool_op(expression)
        elif isinstance(expression, Compare):
            return self._handle_comparison(expression)
        elif isinstance(expression, UnaryOp):
            return self._handle_unary_op(expression)
        elif isinstance(expression, Call):
            return self._handle_call(expression)

        
    @classmethod 
    def from_string(self, parser, filter_string):
        try:
            parsed = ast.parse(filter_string)
        except SyntaxError:
            raise FilterParseError()

        if not len(parsed.body) == 1:
            raise FilterParseError()

        new_filter = TraceFilter(parser)
        new_filter.filter = new_filter._parse_expression(parsed.body[0].value)
        return new_filter

    @classmethod
    def true(self):
        new_filter = _cparser_defs.trace_record_matcher_spec_s()
        new_filter.type = TRACE_MATCHER_TRUE;
        return TraceFilter(None, new_filter)
        
class RawTraceRecord(Bunch):
    pass

class ProcessMetadata(Bunch):
    pass

class TraceParser(object):
    def __init__(self, filename = None, event_handler = None):
        event_handler_prototype = CFUNCTYPE(None, POINTER(_cparser_defs.trace_parser), c_int, c_void_p, c_void_p)
        self.record_ready = False
        self._handler = event_handler_prototype(make_bound_handler(self))
        self._parser_handle = _cparser_defs.trace_parser()
        self._event_handler = event_handler

        if filename:
            _traces_so.TRACE_PARSER__from_file(byref(self._parser_handle), filename, self._handler, byref(c_int()))
            self.end_offset = self._parser_handle.file_info.end_offset
        else:
            _traces_so.TRACE_PARSER__from_external_stream(byref(self._parser_handle), self._handler, byref(c_int()))



    def _event_handler(self, parser, event_type, event_data, arg):
        print parser, event_type, event_data, arg
        
    def set_color(self, color_enabled):
        _traces_so.TRACE_PARSER__set_color(byref(self._parser_handle), int(color_enabled))

    def set_show_field_names(self, show_field_names):
        _traces_so.TRACE_PARSER__set_show_field_names(byref(self._parser_handle), int(show_field_names))

    def set_relative_ts(self, relative_ts_enabled):
        _traces_so.TRACE_PARSER__set_relative_ts(byref(self._parser_handle), int(relative_ts_enabled))

    def set_indent(self, indent_enabled):
        _traces_so.TRACE_PARSER__set_indent(byref(self._parser_handle), int(indent_enabled))

    def set_filter(self, filter):
        _traces_so.TRACE_PARSER__set_filter(byref(self._parser_handle), byref(filter))
        
    def enable_debug(self, enable_debug = True):
        if (enable_debug):
            mask = 0
        else:
            mask = (1 << 1)
            
        _traces_so.TRACE_PARSER__set_severity_mask(byref(self._parser_handle), int(mask))

    def dump_file(self, filename, verbose = False, tail = False):
        return _traces_so.TRACE_PARSER__dump(byref(self._parser_handle), int(verbose), int(tail))

    def _bunchify_raw_record(self, raw_record_buffer):
        base_bunch = RawTraceRecord(ts = raw_record_buffer.ts,
                           pid = raw_record_buffer.pid,
                           tid = raw_record_buffer.tid,
                           rec_type= raw_record_buffer.rec_type,
                           nesting = raw_record_buffer.nesting,
                           severity = raw_record_buffer.severity)

        # TODO: More fields
        return base_bunch
        
        
    def format_next_record(self):
        _traces_so.TRACE_PARSER__process_next_record_from_file(byref(self._parser_handle))
        if self.record_ready:
            self.record_ready = False
            self._last_record = self._bunchify_raw_record(self.raw_record)
            return self.formatted_record, self._last_record
        else:
            return None, None

    def format_previous_record(self):
        _traces_so.TRACE_PARSER__process_previous_record_from_file(byref(self._parser_handle))
        if self.record_ready:
            self.record_ready = False
            return self.formatted_record, self.raw_record
        else:
            return None, None


    def get_next_n_records(self, n):
        records = [self.format_next_record()
                   for i in xrange(n)]

        return records
    
    def get_previous_n_records(self, n):
        records = [self.format_previous_record()
                   for i in xrange(n)]

        return records

    def _convert_to_nsec(self, raw_time):
        formats = ['%d/%m',
                   '%H:%M',
                   '%H:%M:%S',
                   '%H:%M:%S:%f', 
                   ':%f', 
                   '%d/%m %H:%M:%S:%f']

        for format in formats:
            try:
                result = datetime.strptime(raw_time, format) - datetime.strptime('', '')
                if result:
                    return int(result.total_seconds() * 1000000000)
                
            except ValueError:
                continue

        return None


    def _get_enums(self, raw_metadata, process_metadata, global_metadata):
        type_index = 0
        while raw_metadata.types[type_index].type_name:
            current_type = raw_metadata.types[type_index]
            type_name = current_type.type_name
            process_metadata.enums[type_name] = {}
            value_index = 0
            while current_type.enum_values[value_index].name:
                value = current_type.enum_values[value_index].value
                name = current_type.enum_values[value_index].name
                process_metadata.enums[type_name][value] = name
                # TODO: Figure out what to do with const with same names but different values
                global_metadata['all_const_values'][name] = value
                value_index += 1

            type_index += 1

    def _get_functions(self, raw_metadata, process_metadata):
        for i in xrange(raw_metadata.metadata.contents.log_descriptor_count):
            if raw_metadata.descriptors[i].kind == _cparser_defs.TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY:
                process_metadata.functions.add(raw_metadata.descriptors[i].params[0].const_str)

    def _get_metadata(self):
        self.metadata = {'all_const_values' : {}}
        for i in xrange(_traces_so.BufferParseContextList__element_count(byref(self._parser_handle.buffer_contexts))):
            process_metadata = ProcessMetadata(enums = {}, functions = set())
            self.metadata[self._parser_handle.buffer_contexts.elements[i].id] = process_metadata
            self._get_enums(self._parser_handle.buffer_contexts.elements[i], process_metadata, self.metadata)
            self._get_functions(self._parser_handle.buffer_contexts.elements[i], process_metadata)

    def get_known_metadata_names(self):
        self._get_metadata()
        names = self.metadata['all_const_values'].keys()
        for key, value in self.metadata.items():
            if key == 'all_const_values':
                continue

            names.extend(value.functions)

        return names

    def get_completion_names(self):
        all_names = self.get_known_metadata_names()
        all_names.extend(['_typename(', '_call(', '_', '_procname(', 'and', 'or', 'not', 'severity', 'pid', 'tid'])
        return all_names

    def _get_absolute_timestamp_from_partial_timestamp(self, timestamp):
        trace_time = datetime.utcfromtimestamp(self._last_record.ts / 1000000000.)
        ranges = [(DAY, YEAR, ('month', 'day')),
                  (HOUR, DAY, ('hour',)),
                  (MINUTE, HOUR, ('minute',)),
                  (SECOND, MINUTE, ('second',)),
                  (0, SECOND, ('microsecond',))]
        for low, high, attrs in ranges:
            partial_time = datetime.utcfromtimestamp(timestamp / 1000000000.)
            if low <= timestamp < high:
                for attr in attrs:
                    trace_time = trace_time.replace(**{attr : getattr(partial_time, attr)})

                if low:
                    timestamp = timestamp % low
            
        return int(time.mktime(trace_time.timetuple()) * 1000000000)

    def partial_to_absolute_time(self, time_spec):
        result = self._convert_to_nsec(time_spec)
        if result:
            return self._get_absolute_timestamp_from_partial_timestamp(result)
        else:
            return None
        

    def seek_to_time(self, ts):
        if isinstance(ts, (str, unicode)):
            ts = self.partial_to_absolute_time(ts)
            if not ts:
                return None
        elif not isinstance(ts, (int, long)):
            return None
        
        error_occurred = c_int()
        error_occurred.value = 0
        result = _traces_so.TRACE_PARSER__seek_to_time(byref(self._parser_handle), c_uint64(ts), byref(error_occurred))
        if error_occurred.value:
            return None
        else:
            return c_uint64(result).value

    def find_next_by_expression(self, matcher):
        import time
        result = _traces_so.TRACE_PARSER__find_next_record_by_expression(byref(self._parser_handle), byref(matcher))
        if result == 0:
            return True
        else:
            return False

    def find_previous_by_expression(self, matcher):
        import time
        result = _traces_so.TRACE_PARSER__find_previous_record_by_expression(byref(self._parser_handle), byref(matcher))
        if result == 0:
            return True
        else:
            return False

    def seek_to_start(self):
        return self.seek_to_time(1)

    def seek_to_end(self):
        return self.seek_to_time(2**63)

    def cancel_ongoing_operation(self):
        _traces_so.TRACE_PARSER__cancel_ongoing_operation(byref(self._parser_handle))

    def __del__(self):
        _traces_so.TRACE_PARSER__fini(byref(self._parser_handle))

if __name__ == '__main__':
    #print TraceFilter.from_string('calculate()')
     parser = TraceParser(sys.argv[1])
     parser.set_color(True)
     parser.set_indent(True)
     parser._get_metadata()

    # i = 50;
    # while (i):
    #     print parser.format_next_record()
    #     i -= 1

    # i = 50
    # while (i):
    #     print parser.format_previous_record()
    #     i -= 1
