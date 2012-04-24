#ifndef _CONFIG_H_
#define _CONFIG_H_

#define SHM_PATH "/dev/shm/"
#define TRACE_SHM_ID "_trace_shm_"    

#ifndef ANDROID
#define TRACE_RECORD_BUFFER_RECS  0x100000
#else
#define TRACE_RECORD_BUFFER_RECS  0x100000
#endif

#endif // _CONFIG_H_
