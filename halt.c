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

#include <time.h>
#include <unistd.h>

#include "macros.h"
#include "halt.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif
    
void halt(const char *filename, const char *function, int lineno)
{
    fprintf(stderr, "HALT!!!!! In (%d) %s(%s:%d)", getpid(), filename, function, lineno);
    while (1) {
        sleep(1000);
    }
}

#ifdef __cplusplus
}
#endif
