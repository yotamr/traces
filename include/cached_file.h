#ifndef __CACHED_FILE_H__
#define __CACHED_FILE_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "bool.h"

typedef struct cached_file_s {
    int fd;
    char *cache;
    off_t cache_start_offset;
    off_t cache_end_offset;
    off_t current_offset;
    int cache_size;
} cached_file_t;

void cached_file__init(struct cached_file_s *self);
int cached_file__open(struct cached_file_s *self, const char *pathname, int flags);
bool_t cached_file__is_open(struct cached_file_s *self);
int cached_file__close(struct cached_file_s *self);
long long cached_file__lseek(struct cached_file_s *self, off_t offset, int whence);
int cached_file__read(struct cached_file_s *self, void *buf, size_t count);
int cached_file__fill_cache(struct cached_file_s *self, size_t size);


#endif
