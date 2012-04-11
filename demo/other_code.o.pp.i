# 1 "other_code.cpp"
# 1 "<built-in>"
# 1 "<command-line>"
# 1 "/home/yotam/Code/core-system/traces/trace_lib.h" 1




extern "C" {



# 1 "/home/yotam/Code/core-system/traces/trace_defs.h" 1




 extern "C" {
# 21 "/home/yotam/Code/core-system/traces/trace_defs.h"
enum trace_severity {



TRACE_SEV_FUNC_TRACE = 1, TRACE_SEV_DEBUG = 2, TRACE_SEV_INFO = 3, TRACE_SEV_WARN = 4, TRACE_SEV_ERROR = 5, TRACE_SEV_FATAL = 6,
        TRACE_SEV__INVALID = 0,
        TRACE_SEV__MIN = 1,
        TRACE_SEV__MAX = 6

};

static inline int trace_strcmp(const char *s1, const char *s2)
{
     unsigned char uc1, uc2;



     while (*s1 != '\0' && *s1 == *s2) {
         s1++;
         s2++;
     }


     uc1 = (*(unsigned char *) s1);
     uc2 = (*(unsigned char *) s2);
     return ((uc1 < uc2) ? -1 : (uc1 > uc2));
 }






static inline enum trace_severity trace_function_name_to_severity(const char *function_name) {
    if (trace_strcmp(function_name, "FUNC_TRACE") == 0) { return TRACE_SEV_FUNC_TRACE; } if (trace_strcmp(function_name, "DEBUG") == 0) { return TRACE_SEV_DEBUG; } if (trace_strcmp(function_name, "INFO") == 0) { return TRACE_SEV_INFO; } if (trace_strcmp(function_name, "WARN") == 0) { return TRACE_SEV_WARN; } if (trace_strcmp(function_name, "ERROR") == 0) { return TRACE_SEV_ERROR; } if (trace_strcmp(function_name, "FATAL") == 0) { return TRACE_SEV_FATAL; };

    return TRACE_SEV__INVALID;
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






enum trace_termination_type {
 TRACE_TERMINATION_LAST = 1,
 TRACE_TERMINATION_FIRST = 2
};



static inline int trace_compare_generation(unsigned int a, unsigned int b)
{
 if (a >= 0xc0000000 && b < 0x40000000)
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
 struct trace_record_member;

 struct trace_typedef {
    unsigned is_signed:1;
    unsigned is_ptr:1;
    unsigned is_cstr:1;
    unsigned int_size:4;
 };

 enum trace_type_id {
    TRACE_TYPE_ID_ENUM = 1,
    TRACE_TYPE_ID_RECORD = 2,
    TRACE_TYPE_ID_TYPEDEF = 3
};


struct trace_type_definition {
    enum trace_type_id type_id;
    const char *type_name;
    union {

        void *params;
        struct trace_enum_value *enum_values;
        struct trace_record_member *record_members;
        struct trace_typedef *typedef_definition;
    };
};

 struct trace_enum_value {
    const char *name;
    unsigned int value;
};

struct trace_record_member {
    const char *name;
    unsigned is_simple:1;
    unsigned is_signed:1;
    unsigned is_ptr:1;
    unsigned is_cstr:1;
    unsigned int_size:4;
    struct trace_type_definition *type;
};


struct trace_record {

 unsigned long long ts;
 unsigned short int pid;
 unsigned short int tid;
    short nesting;
 unsigned termination:2;
 unsigned reserved:6;
 unsigned severity:4;
 unsigned rec_type:4;
 unsigned int generation;


 union trace_record_u {
  unsigned char payload[44];
  struct trace_record_typed {
   unsigned int log_id;
   unsigned char payload[0];
  } typed;
  struct trace_record_file_header {
   unsigned char machine_id[0x18];
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
 TRACE_PARAM_FLAG_NUM_8 = 0x001,
 TRACE_PARAM_FLAG_NUM_16 = 0x002,
 TRACE_PARAM_FLAG_NUM_32 = 0x004,
 TRACE_PARAM_FLAG_NUM_64 = 0x008,
 TRACE_PARAM_FLAG_VARRAY = 0x010,
 TRACE_PARAM_FLAG_CSTR = 0x020,

 TRACE_PARAM_FLAG_STR = 0x040,
 TRACE_PARAM_FLAG_BLOB = 0x080,

 TRACE_PARAM_FLAG_UNSIGNED = 0x100,
 TRACE_PARAM_FLAG_HEX = 0x200,
 TRACE_PARAM_FLAG_ZERO = 0x400,
    TRACE_PARAM_FLAG_ENUM = 0x800,
    TRACE_PARAM_FLAG_RECORD = 0x1000,
    TRACE_PARAM_FLAG_ENTER = 0x2000,
    TRACE_PARAM_FLAG_LEAVE = 0x4000,
    TRACE_PARAM_FLAG_TYPEDEF = 0x8000,
    TRACE_PARAM_FLAG_NAMED_PARAM = 0x10000,
};

struct trace_param_descriptor {
 unsigned long flags;
    const char *param_name;
    union {
        const char *str;
        const char *const_str;
        const char *type_name;
    };
};

struct trace_log_descriptor {
    enum trace_log_descriptor_kind kind;
    struct trace_param_descriptor *params;
};

struct trace_metadata_region {
    char name[0x100];
    void *base_address;
    unsigned long log_descriptor_count;
    unsigned long type_definition_count;
    char data[0];
};


}
# 10 "/home/yotam/Code/core-system/traces/trace_lib.h" 2
# 1 "/usr/include/x86_64-linux-gnu/sys/syscall.h" 1 3 4
# 25 "/usr/include/x86_64-linux-gnu/sys/syscall.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/asm/unistd.h" 1 3 4



# 1 "/usr/include/x86_64-linux-gnu/asm/unistd_64.h" 1 3 4
# 16 "/usr/include/x86_64-linux-gnu/asm/unistd_64.h" 3 4




























































































































































































































































































































































































































































































































































































































































































# 5 "/usr/include/x86_64-linux-gnu/asm/unistd.h" 2 3 4
# 26 "/usr/include/x86_64-linux-gnu/sys/syscall.h" 2 3 4






# 1 "/usr/include/x86_64-linux-gnu/bits/syscall.h" 1 3 4






# 1 "/usr/include/x86_64-linux-gnu/bits/wordsize.h" 1 3 4
# 8 "/usr/include/x86_64-linux-gnu/bits/syscall.h" 2 3 4
# 33 "/usr/include/x86_64-linux-gnu/sys/syscall.h" 2 3 4
# 11 "/home/yotam/Code/core-system/traces/trace_lib.h" 2
# 1 "/usr/include/time.h" 1 3 4
# 28 "/usr/include/time.h" 3 4
# 1 "/usr/include/features.h" 1 3 4
# 323 "/usr/include/features.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/predefs.h" 1 3 4
# 324 "/usr/include/features.h" 2 3 4
# 356 "/usr/include/features.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/sys/cdefs.h" 1 3 4
# 353 "/usr/include/x86_64-linux-gnu/sys/cdefs.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/wordsize.h" 1 3 4
# 354 "/usr/include/x86_64-linux-gnu/sys/cdefs.h" 2 3 4
# 357 "/usr/include/features.h" 2 3 4
# 388 "/usr/include/features.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/gnu/stubs.h" 1 3 4



# 1 "/usr/include/x86_64-linux-gnu/bits/wordsize.h" 1 3 4
# 5 "/usr/include/x86_64-linux-gnu/gnu/stubs.h" 2 3 4




# 1 "/usr/include/x86_64-linux-gnu/gnu/stubs-64.h" 1 3 4
# 10 "/usr/include/x86_64-linux-gnu/gnu/stubs.h" 2 3 4
# 389 "/usr/include/features.h" 2 3 4
# 29 "/usr/include/time.h" 2 3 4

extern "C" {







# 1 "/usr/lib/gcc/x86_64-linux-gnu/4.6.1/include/stddef.h" 1 3 4
# 212 "/usr/lib/gcc/x86_64-linux-gnu/4.6.1/include/stddef.h" 3 4
typedef long unsigned int size_t;
# 39 "/usr/include/time.h" 2 3 4



# 1 "/usr/include/x86_64-linux-gnu/bits/time.h" 1 3 4
# 43 "/usr/include/time.h" 2 3 4
# 56 "/usr/include/time.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/types.h" 1 3 4
# 28 "/usr/include/x86_64-linux-gnu/bits/types.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/wordsize.h" 1 3 4
# 29 "/usr/include/x86_64-linux-gnu/bits/types.h" 2 3 4


typedef unsigned char __u_char;
typedef unsigned short int __u_short;
typedef unsigned int __u_int;
typedef unsigned long int __u_long;


typedef signed char __int8_t;
typedef unsigned char __uint8_t;
typedef signed short int __int16_t;
typedef unsigned short int __uint16_t;
typedef signed int __int32_t;
typedef unsigned int __uint32_t;

typedef signed long int __int64_t;
typedef unsigned long int __uint64_t;







typedef long int __quad_t;
typedef unsigned long int __u_quad_t;
# 131 "/usr/include/x86_64-linux-gnu/bits/types.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/typesizes.h" 1 3 4
# 132 "/usr/include/x86_64-linux-gnu/bits/types.h" 2 3 4


typedef unsigned long int __dev_t;
typedef unsigned int __uid_t;
typedef unsigned int __gid_t;
typedef unsigned long int __ino_t;
typedef unsigned long int __ino64_t;
typedef unsigned int __mode_t;
typedef unsigned long int __nlink_t;
typedef long int __off_t;
typedef long int __off64_t;
typedef int __pid_t;
typedef struct { int __val[2]; } __fsid_t;
typedef long int __clock_t;
typedef unsigned long int __rlim_t;
typedef unsigned long int __rlim64_t;
typedef unsigned int __id_t;
typedef long int __time_t;
typedef unsigned int __useconds_t;
typedef long int __suseconds_t;

typedef int __daddr_t;
typedef long int __swblk_t;
typedef int __key_t;


typedef int __clockid_t;


typedef void * __timer_t;


typedef long int __blksize_t;




typedef long int __blkcnt_t;
typedef long int __blkcnt64_t;


typedef unsigned long int __fsblkcnt_t;
typedef unsigned long int __fsblkcnt64_t;


typedef unsigned long int __fsfilcnt_t;
typedef unsigned long int __fsfilcnt64_t;

typedef long int __ssize_t;



typedef __off64_t __loff_t;
typedef __quad_t *__qaddr_t;
typedef char *__caddr_t;


typedef long int __intptr_t;


typedef unsigned int __socklen_t;
# 57 "/usr/include/time.h" 2 3 4



typedef __clock_t clock_t;



# 74 "/usr/include/time.h" 3 4


typedef __time_t time_t;



# 92 "/usr/include/time.h" 3 4
typedef __clockid_t clockid_t;
# 104 "/usr/include/time.h" 3 4
typedef __timer_t timer_t;
# 120 "/usr/include/time.h" 3 4
struct timespec
  {
    __time_t tv_sec;
    long int tv_nsec;
  };








struct tm
{
  int tm_sec;
  int tm_min;
  int tm_hour;
  int tm_mday;
  int tm_mon;
  int tm_year;
  int tm_wday;
  int tm_yday;
  int tm_isdst;


  long int tm_gmtoff;
  __const char *tm_zone;




};








struct itimerspec
  {
    struct timespec it_interval;
    struct timespec it_value;
  };


struct sigevent;





typedef __pid_t pid_t;








extern clock_t clock (void) throw ();


extern time_t time (time_t *__timer) throw ();


extern double difftime (time_t __time1, time_t __time0)
     throw () __attribute__ ((__const__));


extern time_t mktime (struct tm *__tp) throw ();





extern size_t strftime (char *__restrict __s, size_t __maxsize,
   __const char *__restrict __format,
   __const struct tm *__restrict __tp) throw ();





extern char *strptime (__const char *__restrict __s,
         __const char *__restrict __fmt, struct tm *__tp)
     throw ();





# 1 "/usr/include/xlocale.h" 1 3 4
# 28 "/usr/include/xlocale.h" 3 4
typedef struct __locale_struct
{

  struct __locale_data *__locales[13];


  const unsigned short int *__ctype_b;
  const int *__ctype_tolower;
  const int *__ctype_toupper;


  const char *__names[13];
} *__locale_t;


typedef __locale_t locale_t;
# 216 "/usr/include/time.h" 2 3 4

extern size_t strftime_l (char *__restrict __s, size_t __maxsize,
     __const char *__restrict __format,
     __const struct tm *__restrict __tp,
     __locale_t __loc) throw ();



extern char *strptime_l (__const char *__restrict __s,
    __const char *__restrict __fmt, struct tm *__tp,
    __locale_t __loc) throw ();






extern struct tm *gmtime (__const time_t *__timer) throw ();



extern struct tm *localtime (__const time_t *__timer) throw ();





extern struct tm *gmtime_r (__const time_t *__restrict __timer,
       struct tm *__restrict __tp) throw ();



extern struct tm *localtime_r (__const time_t *__restrict __timer,
          struct tm *__restrict __tp) throw ();





extern char *asctime (__const struct tm *__tp) throw ();


extern char *ctime (__const time_t *__timer) throw ();







extern char *asctime_r (__const struct tm *__restrict __tp,
   char *__restrict __buf) throw ();


extern char *ctime_r (__const time_t *__restrict __timer,
        char *__restrict __buf) throw ();




extern char *__tzname[2];
extern int __daylight;
extern long int __timezone;




extern char *tzname[2];



extern void tzset (void) throw ();



extern int daylight;
extern long int timezone;





extern int stime (__const time_t *__when) throw ();
# 313 "/usr/include/time.h" 3 4
extern time_t timegm (struct tm *__tp) throw ();


extern time_t timelocal (struct tm *__tp) throw ();


extern int dysize (int __year) throw () __attribute__ ((__const__));
# 328 "/usr/include/time.h" 3 4
extern int nanosleep (__const struct timespec *__requested_time,
        struct timespec *__remaining);



extern int clock_getres (clockid_t __clock_id, struct timespec *__res) throw ();


extern int clock_gettime (clockid_t __clock_id, struct timespec *__tp) throw ();


extern int clock_settime (clockid_t __clock_id, __const struct timespec *__tp)
     throw ();






extern int clock_nanosleep (clockid_t __clock_id, int __flags,
       __const struct timespec *__req,
       struct timespec *__rem);


extern int clock_getcpuclockid (pid_t __pid, clockid_t *__clock_id) throw ();




extern int timer_create (clockid_t __clock_id,
    struct sigevent *__restrict __evp,
    timer_t *__restrict __timerid) throw ();


extern int timer_delete (timer_t __timerid) throw ();


extern int timer_settime (timer_t __timerid, int __flags,
     __const struct itimerspec *__restrict __value,
     struct itimerspec *__restrict __ovalue) throw ();


extern int timer_gettime (timer_t __timerid, struct itimerspec *__value)
     throw ();


extern int timer_getoverrun (timer_t __timerid) throw ();
# 390 "/usr/include/time.h" 3 4
extern int getdate_err;
# 399 "/usr/include/time.h" 3 4
extern struct tm *getdate (__const char *__string);
# 413 "/usr/include/time.h" 3 4
extern int getdate_r (__const char *__restrict __string,
        struct tm *__restrict __resbufp);


}
# 12 "/home/yotam/Code/core-system/traces/trace_lib.h" 2



    extern long int syscall (long int __sysno, ...) throw ();






extern struct trace_buffer *current_trace_buffer;
extern struct trace_log_descriptor __static_log_information_start;
extern struct trace_log_descriptor __static_log_information_end;
extern struct trace_type_definition *__type_information_start;
extern __thread unsigned short trace_current_nesting;

static inline unsigned short int trace_get_pid(void)
{
    static __thread int pid_cache = 0;
    if (pid_cache)
  return pid_cache;
 pid_cache = syscall(39);
 return pid_cache;
}

static inline unsigned short int trace_get_tid(void)
{
    static __thread int tid_cache = 0;
    if (tid_cache)
  return tid_cache;
 tid_cache = syscall(186);
 return tid_cache;
}

static inline unsigned long long trace_get_nsec(void)
{
     struct timespec tv;
     clock_gettime(0, &tv);
     return ((unsigned long long) tv.tv_sec * 1000000000) + tv.tv_nsec;
}

static inline void trace_increment_nesting_level(void)
{
    trace_current_nesting++;
}

static inline void trace_decrement_nesting_level(void)
{
    trace_current_nesting--;
}

static inline unsigned short trace_get_nesting_level(void)
{
    return trace_current_nesting;
}



static inline int trace_strnlen(const char *c, int l)
{
 int r = 0;

 while (*c && l >= 0) {
  r++;
  c++;
  l--;
 }

 return r;
}

struct trace_records_mutable_metadata {
 int current_record;
 int reserved[14];

 unsigned long long latest_flushed_ts;
};

struct trace_records_immutable_metadata {
 unsigned int max_records;
 unsigned int max_records_mask;
 unsigned int max_records_shift;
 unsigned int severity_type;
};

struct trace_records {
 struct trace_records_immutable_metadata imutab;
 struct trace_records_mutable_metadata mutab;
 struct trace_record records[0x100000];
};


struct trace_buffer {
    unsigned int pid;
    union {
        struct trace_records _all_records[(3)];
        struct {
            struct trace_records _funcs;
            struct trace_records _debug;
            struct trace_records _other;
        } records;
    } u;
};

static inline void set_current_trace_buffer_ptr(struct trace_buffer *trace_buffer_ptr)
{
    current_trace_buffer = trace_buffer_ptr;
}

static inline struct trace_record *trace_get_record(enum trace_severity severity, unsigned int *generation)
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

 record = &records->records[record_index % 0x100000];
 return record;
}

}
# 1 "<command-line>" 2
# 1 "/home/yotam/Code/core-system/traces/trace_user.h" 1




extern "C" {


void TRACE__fini(void);

typedef unsigned char hex_t;
# 22 "/home/yotam/Code/core-system/traces/trace_user.h"
void DEBUG(...) __attribute__((error("traces: Trace symbol name should not appear in final code, this is a bug. Contact Yotam Rubin <yotamrubin@gmail.com> and report a bug")));
void WARN(...) __attribute__((error("traces: Trace symbol name should not appear in final code, this is a bug. Contact Yotam Rubin <yotamrubin@gmail.com> and report a bug")));
void INFO(...) __attribute__((error("traces: Trace symbol name should not appear in final code, this is a bug. Contact Yotam Rubin <yotamrubin@gmail.com> and report a bug")));
void ERROR(...) __attribute__((error("traces: Trace symbol name should not appear in final code, this is a bug. Contact Yotam Rubin <yotamrubin@gmail.com> and report a bug")));
void FATAL(...) __attribute__((error("traces: Trace symbol name should not appear in final code, this is a bug. Contact Yotam Rubin <yotamrubin@gmail.com> and report a bug")));
# 53 "/home/yotam/Code/core-system/traces/trace_user.h"
}
# 1 "<command-line>" 2
# 1 "other_code.cpp"
