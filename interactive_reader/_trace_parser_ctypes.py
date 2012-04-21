from ctypes import *

STRING = c_char_p


class cached_file_s(Structure):
    pass
__off_t = c_long
off_t = __off_t
cached_file_s._fields_ = [
    ('fd', c_int),
    ('cache', c_char * 32768),
    ('cache_start_offset', off_t),
    ('cache_end_offset', off_t),
    ('current_offset', off_t),
    ('file_end_offset', off_t),
]
class trace_type_definition(Structure):
    pass

# values for enumeration 'trace_type_id'
TRACE_TYPE_ID_ENUM = 1
TRACE_TYPE_ID_RECORD = 2
TRACE_TYPE_ID_TYPEDEF = 3
trace_type_id = c_int # enum
class N21trace_type_definition4DOT_30E(Union):
    pass
class trace_enum_value(Structure):
    pass
N21trace_type_definition4DOT_30E._fields_ = [
    ('params', c_void_p),
    ('enum_values', POINTER(trace_enum_value)),
]
trace_type_definition._anonymous_ = ['_0']
trace_type_definition._fields_ = [
    ('type_id', trace_type_id),
    ('type_name', STRING),
    ('_0', N21trace_type_definition4DOT_30E),
]
trace_enum_value._fields_ = [
    ('name', STRING),
    ('value', c_uint),
]
class trace_record(Structure):
    pass
class trace_record_u(Union):
    pass
class trace_record_typed(Structure):
    pass
trace_record_typed._fields_ = [
    ('log_id', c_uint),
    ('payload', c_ubyte * 0),
]
class trace_record_file_header(Structure):
    pass
trace_record_file_header._fields_ = [
    ('machine_id', c_ubyte * 24),
    ('boot_time', c_ulonglong),
]
class trace_record_metadata(Structure):
    pass
trace_record_metadata._fields_ = [
    ('metadata_size_bytes', c_uint),
]
class trace_record_dump_header(Structure):
    pass
trace_record_dump_header._fields_ = [
    ('prev_dump_offset', c_uint),
    ('total_dump_size', c_uint),
    ('first_chunk_offset', c_uint),
]
class trace_record_buffer_dump(Structure):
    pass
trace_record_buffer_dump._fields_ = [
    ('last_metadata_offset', c_uint),
    ('prev_chunk_offset', c_uint),
    ('dump_header_offset', c_uint),
    ('ts', c_ulonglong),
    ('records', c_uint),
    ('severity_type', c_uint),
]
trace_record_u._pack_ = 1
trace_record_u._fields_ = [
    ('payload', c_ubyte * 44),
    ('typed', trace_record_typed),
    ('file_header', trace_record_file_header),
    ('metadata', trace_record_metadata),
    ('dump_header', trace_record_dump_header),
    ('buffer_chunk', trace_record_buffer_dump),
]
trace_record._fields_ = [
    ('ts', c_ulonglong),
    ('pid', c_ushort),
    ('tid', c_ushort),
    ('nesting', c_short),
    ('termination', c_uint, 2),
    ('reserved', c_uint, 6),
    ('severity', c_uint, 4),
    ('rec_type', c_uint, 4),
    ('generation', c_uint),
    ('u', trace_record_u),
]
class trace_param_descriptor(Structure):
    pass
class N22trace_param_descriptor4DOT_31E(Union):
    pass
N22trace_param_descriptor4DOT_31E._fields_ = [
    ('str', STRING),
    ('const_str', STRING),
    ('type_name', STRING),
]
trace_param_descriptor._anonymous_ = ['_0']
trace_param_descriptor._fields_ = [
    ('flags', c_ulong),
    ('param_name', STRING),
    ('_0', N22trace_param_descriptor4DOT_31E),
]
class trace_log_descriptor(Structure):
    pass

# values for enumeration 'trace_log_descriptor_kind'
TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY = 0
TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE = 1
TRACE_LOG_DESCRIPTOR_KIND_EXPLICIT = 2
trace_log_descriptor_kind = c_int # enum
trace_log_descriptor._fields_ = [
    ('kind', trace_log_descriptor_kind),
    ('params', POINTER(trace_param_descriptor)),
]
class trace_metadata_region(Structure):
    pass
trace_metadata_region._fields_ = [
    ('name', c_char * 256),
    ('base_address', c_void_p),
    ('log_descriptor_count', c_ulong),
    ('type_definition_count', c_ulong),
    ('data', c_char * 0),
]
class trace_parser_buffer_context(Structure):
    pass
trace_parser_buffer_context._fields_ = [
    ('metadata', POINTER(trace_metadata_region)),
    ('metadata_size', c_ulong),
    ('current_metadata_offset', c_ulong),
    ('metadata_read', c_ulong),
    ('descriptors', POINTER(trace_log_descriptor)),
    ('types', POINTER(trace_type_definition)),
    ('name', c_char * 256),
    ('id', c_uint),
]
class trace_record_accumulator(Structure):
    pass
trace_record_accumulator._fields_ = [
    ('accumulated_data', c_char * 40960),
    ('data_offset', c_uint),
    ('tid', c_ushort),
]
class BufferParseContextList_s(Structure):
    pass
BufferParseContextList_s._fields_ = [
    ('element_count', c_int),
    ('elements', trace_parser_buffer_context * 20),
]
class RecordsAccumulatorList_s(Structure):
    pass
RecordsAccumulatorList_s._fields_ = [
    ('element_count', c_int),
    ('elements', trace_record_accumulator * 20),
]
class parser_complete_typed_record(Structure):
    pass
parser_complete_typed_record._fields_ = [
    ('record', POINTER(trace_record)),
    ('buffer', POINTER(trace_parser_buffer_context)),
]
class trace_file_info(Structure):
    pass
cached_file_t = cached_file_s
trace_file_info._fields_ = [
    ('filename', c_char * 256),
    ('machine_id', c_char * 256),
    ('boot_time', c_long),
    ('file_handle', cached_file_t),
]
class record_dump_context_s(Structure):
    pass
record_dump_context_s._fields_ = [
    ('start_offset', c_longlong),
    ('current_offset', c_longlong),
    ('end_offset', c_longlong),
]
class buffer_dump_context_s(Structure):
    pass
buffer_dump_context_s._fields_ = [
    ('record_dump_contexts', record_dump_context_s * 150),
    ('end_offset', c_longlong),
    ('previous_dump_offset', c_longlong),
    ('file_offset', c_longlong),
    ('num_chunks', c_uint),
]
class trace_record_matcher_spec_s(Structure):
    pass

# values for enumeration 'trace_record_matcher_type'
TRACE_MATCHER_TRUE = 0
TRACE_MATCHER_FALSE = 1
TRACE_MATCHER_OR = 2
TRACE_MATCHER_AND = 3
TRACE_MATCHER_NOT = 4
TRACE_MATCHER_PID = 5
TRACE_MATCHER_TID = 6
TRACE_MATCHER_TIMERANGE = 7
TRACE_MATCHER_LOGID = 8
TRACE_MATCHER_SEVERITY = 9
TRACE_MATCHER_FUNCTION = 10
TRACE_MATCHER_TYPE = 11
TRACE_MATCHER_LOG_PARAM_VALUE = 12
TRACE_MATCHER_LOG_NAMED_PARAM_VALUE = 13
TRACE_MATCHER_PROCESS_NAME = 14
trace_record_matcher_type = c_int # enum
class trace_record_matcher_data_u(Union):
    pass
class trace_time_range(Structure):
    pass
trace_time_range._fields_ = [
    ('start', c_ulonglong),
    ('end', c_ulonglong),
]
class trace_matcher_named_param_value(Structure):
    pass
trace_matcher_named_param_value._fields_ = [
    ('param_name', c_char * 256),
    ('param_value', c_ulonglong),
]
class trace_record_matcher_binary_operator_params(Structure):
    pass
trace_record_matcher_binary_operator_params._fields_ = [
    ('a', POINTER(trace_record_matcher_spec_s)),
    ('b', POINTER(trace_record_matcher_spec_s)),
]
class trace_record_matcher_unary_operator_params(Structure):
    pass
trace_record_matcher_unary_operator_params._fields_ = [
    ('param', POINTER(trace_record_matcher_spec_s)),
]
trace_record_matcher_data_u._fields_ = [
    ('pid', c_ushort),
    ('tid', c_ushort),
    ('log_id', c_uint),
    ('severity', c_uint),
    ('time_range', trace_time_range),
    ('function_name', c_char * 256),
    ('type_name', c_char * 256),
    ('process_name', c_char * 256),
    ('param_value', c_ulonglong),
    ('named_param_value', trace_matcher_named_param_value),
    ('binary_operator_parameters', trace_record_matcher_binary_operator_params),
    ('unary_operator_parameters', trace_record_matcher_unary_operator_params),
]
trace_record_matcher_spec_s._fields_ = [
    ('type', trace_record_matcher_type),
    ('u', trace_record_matcher_data_u),
]
class trace_parser(Structure):
    pass
BufferParseContextList = BufferParseContextList_s
RecordsAccumulatorList = RecordsAccumulatorList_s

# values for enumeration 'trace_parser_event_e'
TRACE_PARSER_COMPLETE_TYPED_RECORD_PROCESSED = 0
TRACE_PARSER_MATCHED_RECORD = 1
TRACE_PARSER_SEARCHING_METADATA = 2
TRACE_PARSER_FOUND_METADATA = 3
trace_parser_event_e = c_int # enum
trace_parser_event_handler_t = CFUNCTYPE(None, POINTER(trace_parser), trace_parser_event_e, c_void_p, c_void_p)
class _IO_FILE(Structure):
    pass
FILE = _IO_FILE

# values for enumeration 'trace_input_stream_type'
TRACE_INPUT_STREAM_TYPE_NONSEEKABLE = 0
TRACE_INPUT_STREAM_TYPE_SEEKABLE_FILE = 1
trace_input_stream_type = c_int # enum
trace_parser._fields_ = [
    ('fd', c_int),
    ('file_info', trace_file_info),
    ('buffer_contexts', BufferParseContextList),
    ('records_accumulators', RecordsAccumulatorList),
    ('buffer_dump_context', buffer_dump_context_s),
    ('event_handler', trace_parser_event_handler_t),
    ('max_ts', c_ulonglong),
    ('arg', c_void_p),
    ('out_file', POINTER(FILE)),
    ('color', c_int),
    ('always_hex', c_int),
    ('indent', c_int),
    ('relative_ts', c_int),
    ('record_filter', trace_record_matcher_spec_s),
    ('ignored_records_count', c_uint),
    ('stream_type', trace_input_stream_type),
]
class _G_fpos_t(Structure):
    pass
class __mbstate_t(Structure):
    pass
class N11__mbstate_t4DOT_26E(Union):
    pass
N11__mbstate_t4DOT_26E._fields_ = [
    ('__wch', c_uint),
    ('__wchb', c_char * 4),
]
__mbstate_t._fields_ = [
    ('__count', c_int),
    ('__value', N11__mbstate_t4DOT_26E),
]
_G_fpos_t._fields_ = [
    ('__pos', __off_t),
    ('__state', __mbstate_t),
]
class _G_fpos64_t(Structure):
    pass
__off64_t = c_long
_G_fpos64_t._fields_ = [
    ('__pos', __off64_t),
    ('__state', __mbstate_t),
]
class _IO_jump_t(Structure):
    pass
_IO_jump_t._fields_ = [
]
class _IO_marker(Structure):
    pass
_IO_marker._fields_ = [
    ('_next', POINTER(_IO_marker)),
    ('_sbuf', POINTER(_IO_FILE)),
    ('_pos', c_int),
]
_IO_lock_t = None
size_t = c_ulong
_IO_FILE._fields_ = [
    ('_flags', c_int),
    ('_IO_read_ptr', STRING),
    ('_IO_read_end', STRING),
    ('_IO_read_base', STRING),
    ('_IO_write_base', STRING),
    ('_IO_write_ptr', STRING),
    ('_IO_write_end', STRING),
    ('_IO_buf_base', STRING),
    ('_IO_buf_end', STRING),
    ('_IO_save_base', STRING),
    ('_IO_backup_base', STRING),
    ('_IO_save_end', STRING),
    ('_markers', POINTER(_IO_marker)),
    ('_chain', POINTER(_IO_FILE)),
    ('_fileno', c_int),
    ('_flags2', c_int),
    ('_old_offset', __off_t),
    ('_cur_column', c_ushort),
    ('_vtable_offset', c_byte),
    ('_shortbuf', c_char * 1),
    ('_lock', POINTER(_IO_lock_t)),
    ('_offset', __off64_t),
    ('__pad1', c_void_p),
    ('__pad2', c_void_p),
    ('__pad3', c_void_p),
    ('__pad4', c_void_p),
    ('__pad5', size_t),
    ('_mode', c_int),
    ('_unused2', c_char * 20),
]
class _IO_FILE_plus(Structure):
    pass
_IO_FILE_plus._fields_ = [
]
class _IO_cookie_io_functions_t(Structure):
    pass
__ssize_t = c_long
__io_read_fn = CFUNCTYPE(__ssize_t, c_void_p, STRING, size_t)
__io_write_fn = CFUNCTYPE(__ssize_t, c_void_p, STRING, size_t)
__io_seek_fn = CFUNCTYPE(c_int, c_void_p, POINTER(__off64_t), c_int)
__io_close_fn = CFUNCTYPE(c_int, c_void_p)
_IO_cookie_io_functions_t._fields_ = [
    ('read', POINTER(__io_read_fn)),
    ('write', POINTER(__io_write_fn)),
    ('seek', POINTER(__io_seek_fn)),
    ('close', POINTER(__io_close_fn)),
]
class _IO_cookie_file(Structure):
    pass
_IO_cookie_file._fields_ = [
]
class _pthread_cleanup_buffer(Structure):
    pass
_pthread_cleanup_buffer._fields_ = [
    ('__routine', CFUNCTYPE(None, c_void_p)),
    ('__arg', c_void_p),
    ('__canceltype', c_int),
    ('__prev', POINTER(_pthread_cleanup_buffer)),
]
class _4DOT_23(Structure):
    pass
class N4DOT_234DOT_24E(Structure):
    pass
__jmp_buf = c_long * 8
N4DOT_234DOT_24E._fields_ = [
    ('__cancel_jmp_buf', __jmp_buf),
    ('__mask_was_saved', c_int),
]
_4DOT_23._fields_ = [
    ('__cancel_jmp_buf', N4DOT_234DOT_24E * 1),
    ('__pad', c_void_p * 4),
]
class __pthread_cleanup_frame(Structure):
    pass
__pthread_cleanup_frame._fields_ = [
    ('__cancel_routine', CFUNCTYPE(None, c_void_p)),
    ('__cancel_arg', c_void_p),
    ('__do_it', c_int),
    ('__cancel_type', c_int),
]
class __jmp_buf_tag(Structure):
    pass
__jmp_buf_tag._fields_ = [
]
class obstack(Structure):
    pass
obstack._fields_ = [
]
class timespec(Structure):
    pass
__time_t = c_long
timespec._fields_ = [
    ('tv_sec', __time_t),
    ('tv_nsec', c_long),
]
class tm(Structure):
    pass
tm._fields_ = [
    ('tm_sec', c_int),
    ('tm_min', c_int),
    ('tm_hour', c_int),
    ('tm_mday', c_int),
    ('tm_mon', c_int),
    ('tm_year', c_int),
    ('tm_wday', c_int),
    ('tm_yday', c_int),
    ('tm_isdst', c_int),
    ('tm_gmtoff', c_long),
    ('tm_zone', STRING),
]
class itimerspec(Structure):
    pass
itimerspec._fields_ = [
    ('it_interval', timespec),
    ('it_value', timespec),
]
class sigevent(Structure):
    pass
sigevent._fields_ = [
]
class flock(Structure):
    pass
__pid_t = c_int
flock._fields_ = [
    ('l_type', c_short),
    ('l_whence', c_short),
    ('l_start', __off_t),
    ('l_len', __off_t),
    ('l_pid', __pid_t),
]
class flock64(Structure):
    pass
flock64._fields_ = [
    ('l_type', c_short),
    ('l_whence', c_short),
    ('l_start', __off64_t),
    ('l_len', __off64_t),
    ('l_pid', __pid_t),
]
class f_owner_ex(Structure):
    pass

# values for enumeration '__pid_type'
F_OWNER_TID = 0
F_OWNER_PID = 1
F_OWNER_PGRP = 2
F_OWNER_GID = 2
__pid_type = c_int # enum
f_owner_ex._fields_ = [
    ('type', __pid_type),
    ('pid', __pid_t),
]
class __pthread_internal_list(Structure):
    pass
__pthread_internal_list._fields_ = [
    ('__prev', POINTER(__pthread_internal_list)),
    ('__next', POINTER(__pthread_internal_list)),
]
class __pthread_mutex_s(Structure):
    pass
__pthread_list_t = __pthread_internal_list
__pthread_mutex_s._fields_ = [
    ('__lock', c_int),
    ('__count', c_uint),
    ('__owner', c_int),
    ('__nusers', c_uint),
    ('__kind', c_int),
    ('__spins', c_int),
    ('__list', __pthread_list_t),
]
class N14pthread_cond_t3DOT_6E(Structure):
    pass
N14pthread_cond_t3DOT_6E._fields_ = [
    ('__lock', c_int),
    ('__futex', c_uint),
    ('__total_seq', c_ulonglong),
    ('__wakeup_seq', c_ulonglong),
    ('__woken_seq', c_ulonglong),
    ('__mutex', c_void_p),
    ('__nwaiters', c_uint),
    ('__broadcast_seq', c_uint),
]
class N16pthread_rwlock_t3DOT_9E(Structure):
    pass
N16pthread_rwlock_t3DOT_9E._fields_ = [
    ('__lock', c_int),
    ('__nr_readers', c_uint),
    ('__readers_wakeup', c_uint),
    ('__writer_wakeup', c_uint),
    ('__nr_readers_queued', c_uint),
    ('__nr_writers_queued', c_uint),
    ('__writer', c_int),
    ('__shared', c_int),
    ('__pad1', c_ulong),
    ('__pad2', c_ulong),
    ('__flags', c_uint),
]
class sched_param(Structure):
    pass
sched_param._fields_ = [
    ('__sched_priority', c_int),
]
class __sched_param(Structure):
    pass
__sched_param._fields_ = [
    ('__sched_priority', c_int),
]
class cpu_set_t(Structure):
    pass
__cpu_mask = c_ulong
cpu_set_t._fields_ = [
    ('__bits', __cpu_mask * 16),
]
class __sigset_t(Structure):
    pass
__sigset_t._fields_ = [
    ('__val', c_ulong * 16),
]
class stat(Structure):
    pass
__dev_t = c_ulong
__ino_t = c_ulong
__nlink_t = c_ulong
__mode_t = c_uint
__uid_t = c_uint
__gid_t = c_uint
__blksize_t = c_long
__blkcnt_t = c_long
stat._fields_ = [
    ('st_dev', __dev_t),
    ('st_ino', __ino_t),
    ('st_nlink', __nlink_t),
    ('st_mode', __mode_t),
    ('st_uid', __uid_t),
    ('st_gid', __gid_t),
    ('__pad0', c_int),
    ('st_rdev', __dev_t),
    ('st_size', __off_t),
    ('st_blksize', __blksize_t),
    ('st_blocks', __blkcnt_t),
    ('st_atim', timespec),
    ('st_mtim', timespec),
    ('st_ctim', timespec),
    ('__unused', c_long * 3),
]
class stat64(Structure):
    pass
__ino64_t = c_ulong
__blkcnt64_t = c_long
stat64._fields_ = [
    ('st_dev', __dev_t),
    ('st_ino', __ino64_t),
    ('st_nlink', __nlink_t),
    ('st_mode', __mode_t),
    ('st_uid', __uid_t),
    ('st_gid', __gid_t),
    ('__pad0', c_int),
    ('st_rdev', __dev_t),
    ('st_size', __off_t),
    ('st_blksize', __blksize_t),
    ('st_blocks', __blkcnt64_t),
    ('st_atim', timespec),
    ('st_mtim', timespec),
    ('st_ctim', timespec),
    ('__unused', c_long * 3),
]
class timeval(Structure):
    pass
__suseconds_t = c_long
timeval._fields_ = [
    ('tv_sec', __time_t),
    ('tv_usec', __suseconds_t),
]
class __fsid_t(Structure):
    pass
__fsid_t._fields_ = [
    ('__val', c_int * 2),
]
class iovec(Structure):
    pass
iovec._fields_ = [
    ('iov_base', c_void_p),
    ('iov_len', size_t),
]
class fd_set(Structure):
    pass
__fd_mask = c_long
fd_set._fields_ = [
    ('fds_bits', __fd_mask * 16),
]
class __locale_struct(Structure):
    pass
class __locale_data(Structure):
    pass
__locale_struct._fields_ = [
    ('__locales', POINTER(__locale_data) * 13),
    ('__ctype_b', POINTER(c_ushort)),
    ('__ctype_tolower', POINTER(c_int)),
    ('__ctype_toupper', POINTER(c_int)),
    ('__names', STRING * 13),
]
__locale_data._fields_ = [
]
class __va_list_tag(Structure):
    pass
__va_list_tag._fields_ = [
]
__all__ = ['TRACE_TYPE_ID_ENUM', 'N11__mbstate_t4DOT_26E',
           'cpu_set_t', 'F_OWNER_GID', '__pthread_mutex_s',
           'trace_type_definition', 'TRACE_MATCHER_TRUE',
           'N14pthread_cond_t3DOT_6E', '__fsid_t', 'FILE',
           '__off64_t', 'size_t', 'trace_file_info',
           'TRACE_MATCHER_TYPE', 'fd_set', 'trace_parser',
           'N4DOT_234DOT_24E', 'RecordsAccumulatorList', 'tm',
           '__ino64_t', '__cpu_mask', 'TRACE_MATCHER_FUNCTION',
           'trace_record', 'TRACE_INPUT_STREAM_TYPE_NONSEEKABLE',
           '__pthread_internal_list', 'TRACE_MATCHER_PID',
           'F_OWNER_PGRP', 'trace_record_buffer_dump',
           'trace_input_stream_type', 'TRACE_MATCHER_NOT', '__time_t',
           'buffer_dump_context_s', '_G_fpos64_t',
           'trace_record_metadata', '__blksize_t', 'trace_enum_value',
           '_IO_jump_t', '__nlink_t',
           'TRACE_INPUT_STREAM_TYPE_SEEKABLE_FILE',
           'RecordsAccumulatorList_s', 'TRACE_MATCHER_PROCESS_NAME',
           '__io_close_fn', '__va_list_tag', 'sigevent', '__fd_mask',
           'trace_log_descriptor_kind', 'trace_metadata_region',
           'trace_time_range', 'flock', '__sigset_t', '__pid_type',
           'TRACE_TYPE_ID_RECORD', 'trace_param_descriptor',
           'TRACE_MATCHER_SEVERITY', 'TRACE_MATCHER_LOGID',
           '__jmp_buf_tag', 'TRACE_MATCHER_TIMERANGE', '_G_fpos_t',
           '_pthread_cleanup_buffer', '_IO_cookie_io_functions_t',
           'trace_record_dump_header', '__locale_data',
           '_IO_FILE_plus',
           'TRACE_PARSER_COMPLETE_TYPED_RECORD_PROCESSED',
           'BufferParseContextList_s', '__blkcnt_t',
           '__pthread_list_t', 'cached_file_t', 'cached_file_s',
           'TRACE_PARSER_MATCHED_RECORD', '__ino_t',
           'TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE', 'timespec',
           'N16pthread_rwlock_t3DOT_9E', '__mode_t',
           'parser_complete_typed_record', '__sched_param',
           'BufferParseContextList', 'trace_record_u', '__off_t',
           'record_dump_context_s', '__gid_t',
           'TRACE_PARSER_SEARCHING_METADATA', '__ssize_t', 'obstack',
           'trace_record_file_header', '_IO_cookie_file',
           'trace_record_matcher_binary_operator_params',
           '__mbstate_t', 'TRACE_MATCHER_LOG_PARAM_VALUE',
           '__io_seek_fn', 'trace_parser_event_e', '_4DOT_23',
           '__blkcnt64_t', '__dev_t', 'TRACE_TYPE_ID_TYPEDEF',
           'trace_parser_buffer_context', '__suseconds_t',
           'TRACE_MATCHER_TID', '_IO_FILE',
           'TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY', 'sched_param',
           '__locale_struct', '__io_read_fn', 'trace_type_id',
           'f_owner_ex', 'off_t', 'TRACE_MATCHER_FALSE', 'iovec',
           '__jmp_buf', 'stat64',
           'trace_record_matcher_unary_operator_params',
           '__pthread_cleanup_frame',
           'trace_matcher_named_param_value',
           'TRACE_MATCHER_LOG_NAMED_PARAM_VALUE',
           'trace_record_matcher_data_u', 'timeval', '_IO_marker',
           'N21trace_type_definition4DOT_30E', 'F_OWNER_PID', 'stat',
           '__pid_t', 'TRACE_MATCHER_OR',
           'trace_record_matcher_spec_s', '__io_write_fn',
           'TRACE_PARSER_FOUND_METADATA',
           'TRACE_LOG_DESCRIPTOR_KIND_EXPLICIT',
           'trace_log_descriptor',
           'N22trace_param_descriptor4DOT_31E', '_IO_lock_t',
           'itimerspec', 'trace_record_accumulator',
           'TRACE_MATCHER_AND', 'F_OWNER_TID', 'flock64',
           'trace_record_typed', '__uid_t',
           'trace_record_matcher_type',
           'trace_parser_event_handler_t']
