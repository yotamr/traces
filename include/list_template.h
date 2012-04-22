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

#ifndef MAX_ELEMENTS
	#define MAX_ELEMENTS (20)
#endif

#include "bool.h"
#include "macros.h"
#include <string.h>
#include <pthread.h>

/* These macros assume the following: 
  - listdatatype is defined to hold the name of the datatype in the list 
  - listname is defined to hold the name of list 
  - MAX_ELEMENTS is defined to the hold the number of max elements in the list
*/


#define CREATE_LIST_PROTOTYPE(listname, listdatatype)                   \
	typedef struct listname##_s {                                       \
	int element_count;                                                  \
	listdatatype elements[MAX_ELEMENTS];                                \
} listname;                                                             \
                                                                        \
void listname ## __##init(listname *self);                              \
void listname ## __##clear(listname *self);                             \
void listname ## __##fini(listname *self);                              \
int listname##__from_buffer(listname *self, char *buffer, int buffer_size); \
int listname##__add_element(listname *self, listdatatype *element);     \
int listname##__allocate_element(listname *self); \
int listname##__get_element(listname *self, int __index, listdatatype *output_element); \
int listname##__get_element_ptr(listname *self, int __index, listdatatype **element_ptr); \
int listname##__remove_element(listname *self, int __index);              \
int listname##__element_count(listname *self);                          \
int listname##__last_element_index(listname *self);                     \
int listname##__dequeue(listname *self, listdatatype *output_element);  \
int listname##__find_element(listname *self, listdatatype *element);    \
bool_t listname##__insertable(listname *self);


#define CREATE_LIST_IMPLEMENTATION(listname, listdatatype)              \
void listname ## __##init(listname *self)                               \
{                                                                       \
	memset(self, 0, sizeof(*self));                                     \
}                                                                       \
                                                                        \
int listname##__from_buffer(listname *self, char *buffer, int buffer_size) \
{                                                                       \
	listname *other = (listname *) buffer;                              \
	listname ## __##init(self);                                         \
	if (buffer_size != sizeof(*self)) {                                 \
		return -1;                                                      \
	}                                                                   \
	memcpy(&self->elements, other->elements, buffer_size);              \
	self->element_count = other->element_count;                         \
	return 0;                                                           \
}                                                                       \
                                                                        \
void listname ## __clear(listname *self) {                              \
	self->element_count = 0;                                            \
}                                                                       \
                                                                        \
void listname ## __##fini(listname *self)                               \
{                                                                       \
	memset(self, 0, sizeof(*self));                                     \
}                                                                       \
                                                                        \
int listname##__add_element(listname *self, listdatatype *element)      \
{                                                                       \
	if (MAX_ELEMENTS == listname##__element_count(self)) {              \
		return -1;                                                      \
	}                                                                   \
	memcpy(&self->elements[self->element_count], element, sizeof(*element)); \
	self->element_count++;                                              \
	return 0;                                                           \
}                                                                       \
                                                                        \
int listname##__allocate_element(listname *self)                        \
{                                                                       \
	if (MAX_ELEMENTS == listname##__element_count(self)) {              \
		return -1;                                                      \
	}                                                                   \
	self->element_count++;                                              \
	return 0;                                                           \
}                                                                       \
                                                                        \
                                                                        \
int listname##__get_element(listname *self, int __index, listdatatype *output_element) \
{                                                                       \
	int rc = 0;                                                         \
	if (__index >= self->element_count) {                                 \
		memset(output_element, 0, sizeof(*output_element));             \
		rc = -1;                                                        \
		goto Exit;                                                      \
	}                                                                   \
                                                                        \
	memcpy(output_element, &self->elements[__index], sizeof(*output_element)); \
Exit:                                                                   \
	return rc;                                                          \
}                                                                       \
                                                                        \
int listname##__get_element_ptr(listname *self, int __index, listdatatype **output_element_ptr) \
{                                                                       \
	int rc = 0;                                                         \
	if (__index >= self->element_count) {                                 \
		rc = -1;                                                        \
		goto Exit;                                                      \
	}                                                                   \
                                                                        \
	*output_element_ptr = &self->elements[__index];                       \
Exit:                                                                   \
	return rc;                                                          \
}                                                                       \
                                                                        \
int listname##__remove_element(listname *self, int __index)               \
{                                                                       \
	int size_of_moved_elements = 0;                                     \
                                                                        \
	if (__index >= listname##__element_count(self)) {                     \
		return -1;                                                      \
	}                                                                   \
                                                                        \
	size_of_moved_elements = sizeof(self->elements[__index]) * (self->element_count - __index - 1); \
	if (!size_of_moved_elements) { self->element_count--; return 0; } \
	memmove(&self->elements[__index], &self->elements[__index + 1], size_of_moved_elements); \
                                                                        \
	self->element_count--;                                              \
                                                                        \
	return 0;                                                           \
                                                                        \
}                                                                       \
                                                                        \
int listname##__dequeue(listname *self, listdatatype *output_element)   \
{                                                                       \
	int rc = -1;                                                        \
	if (0 == listname##__element_count(self)) {                         \
		rc = -1;                                                        \
		goto Exit;                                                      \
	}                                                                   \
                                                                        \
	listname##__get_element(self, 0, output_element);                   \
	listname##__remove_element(self, 0);                                \
    rc = 0;                                                             \
Exit:                                                                   \
	return rc;                                                          \
                                                                        \
}                                                                       \
                                                                        \
int listname##__element_count(listname *self)                           \
{                                                                       \
	int rc;                                                             \
	rc = self->element_count;                                           \
                                                                        \
	return rc;                                                          \
}                                                                       \
                                                                        \
int listname##__last_element_index(listname *self)                      \
{                                                                       \
	return (listname##__element_count(self) - 1);                       \
}                                                                       \
                                                                        \
int listname##__find_element(listname *self, listdatatype *element)     \
{                                                                       \
	int i = 0;                                                          \
	int element_count = 0;                                              \
	int rc = -1;                                                        \
	listdatatype tmp_element		;                                   \
                                                                        \
	element_count = listname##__element_count(self);                    \
	while(i < element_count) {                                          \
		listname##__get_element(self, i, &tmp_element);                 \
		rc = memcmp(element, &tmp_element, sizeof(*element));           \
		if (0 == rc) {                                                  \
			return i;                                                   \
		}                                                               \
		i++;                                                            \
	}                                                                   \
                                                                        \
	if (0 != rc) {                                                      \
		rc = -1;                                                        \
	}                                                                   \
                                                                        \
	return rc;                                                          \
}                                                                       \
                                                                        \
bool_t listname##__insertable(listname *self) {                         \
	return (!(listname##__element_count(self) == MAX_ELEMENTS));        \
}
