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

#ifndef __TRACE_USER_H__
#define __TRACE_USER_H__

#ifdef __cplusplus
extern "C" {
#endif

void TRACE__fini(void);// __attribute__((destructor));
    
typedef unsigned char hex_t;
#define HEX_REPR(x, size) (hex_t (*)[size]) x

 #ifndef __has_attribute         
  #define __has_attribute(x) 0
#endif
    
#ifdef __TRACE_INSTRUMENTATION
#define CALL_INVALID __attribute__((error("traces: Trace symbol name should not appear in final code, this is a bug. Contact Yotam Rubin <yotamrubin@gmail.com> and report a bug")))
#ifdef __cplusplus

    
void DEBUG(...) CALL_INVALID;
void WARN(...) CALL_INVALID;
void INFO(...) CALL_INVALID;
void ERROR(...) CALL_INVALID;
void FATAL(...) CALL_INVALID;
    
#else
void DEBUG() CALL_INVALID;
void WARN() CALL_INVALID;
void INFO() CALL_INVALID;
void ERROR() CALL_INVALID;
void FATAL() CALL_INVALID;

#endif /* __cplusplus */
#else /* __TRACE_INSTRUMENTATION */
#ifdef __cplusplus    
void DEBUG(...);
void WARN(...);
void INFO(...);
void ERROR(...);
void FATAL(...);    
#else
void DEBUG();
void WARN();
void INFO();
void ERROR();
void FATAL();

#endif /* __cplusplus */
#endif /* __TRACE_INSTRUMENTATION */    
#ifdef __cplusplus
}
#endif

#endif 
