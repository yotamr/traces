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

#ifndef __OBJECT_POOL_H__
#define __OBJECT_POOL_H__

#include <stdlib.h>

#define OBJECT_POOL(name, type, count)                          \
typedef struct {                                                \
    bool_t allocated;                                           \
    type data;                                                  \
} name##__element_t;                                            \
                                                                \
typedef name##__element_t name##_t[count];                      \
                                                                \
int name##__deallocate(name##_t self, type *to_deallocate) {    \
    int i;                                                      \
    for (i = 0; i < count; i++) {                               \
        if (to_deallocate == &self[i].data) {                   \
            memset(&self[i], 0, sizeof(type));                  \
            self[i].allocated = FALSE;                          \
            return 0;                                           \
        }                                                       \
    }                                                           \
                                                                \
    return -1;                                                  \
}                                                               \
                                                                \
void name##__init(name##_t self) {                              \
    int i;                                                      \
    for (i = 0; i < count; i++) {                               \
        name##__deallocate(self, &self[i].data);                \
    }                                                           \
}                                                               \
                                                                \
type *name##__allocate(name##_t self) {                         \
    int i;                                                      \
    for (i = 0; i < count; i++) {                               \
        if (!self[i].allocated) {                               \
            self[i].allocated = TRUE;                           \
            return &self[i].data;                               \
        }                                                       \
    }                                                           \
                                                                \
    return NULL;                                                \
}                                                               \
                                                                \
bool_t name##__is_allocated(name##_t self, type *element)       \
{                                                               \
    int i;                                                      \
    for (i = 0; i < count; i++) {                               \
        if (&self[i].data == element) {                         \
            return self[i].allocated;                           \
        }                                                       \
    }                                                           \
                                                                \
    return FALSE;                                               \
}
    


#endif 
