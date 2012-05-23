#ifndef _CONFIG_H_
#define _CONFIG_H_

#define SHM_PATH "/dev/shm/"
#define TRACE_SHM_ID "_trace_shm_"    

#ifndef TRACE_RECORD_BUFFER_RECS
#ifndef ANDROID
#define TRACE_RECORD_BUFFER_RECS  0x10000
#else
#define TRACE_RECORD_BUFFER_RECS  0x100000
#endif /* ANDROID */
#endif /* TRACE_RECORD_BUFFER_RECS */

#endif // _CONFIG_H_
