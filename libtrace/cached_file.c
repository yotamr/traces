#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "cached_file.h"
#include "bool.h"
#include "min_max.h"
#include <stdlib.h>
#include <stdio.h>

#define MAX_CACHE_SIZE (16 * 1024 * 1024)

static off_t end_offset(int fd)
{
    off_t orig_offset = lseek(fd, 0, SEEK_CUR);
    if (-1 == orig_offset) {
        return -1;
    }

    off_t end = lseek(fd, 0, SEEK_END);
    lseek(fd, orig_offset, SEEK_SET);
    return end;
}

int cached_file__open(struct cached_file_s *self, const char *pathname, int flags)
{
    int fd = open(pathname, flags);
    // TODO: Support write operations
    if (flags != O_RDONLY) {
        return -1;
    }
    if (fd < 0) {
        self->fd = -1;
        return -1;
    }
    
    memset(self, 0, sizeof(*self));
    self->fd = fd;
    return 0;
}

int cached_file__close(struct cached_file_s *self)
{
    return close(self->fd);
}

long long cached_file__lseek(struct cached_file_s *self, off_t offset, int whence)
{
    off_t new_offset;
    off_t rc;

    
    if (whence == SEEK_SET) {
        new_offset = offset;
    } else if (whence == SEEK_CUR) {
        new_offset = self->current_offset + offset;
    } else if (whence == SEEK_END) {
        new_offset = end_offset(self->fd) + offset;
    } else {
        return -1;
    }


    if (new_offset < self->cache_end_offset && new_offset >= self->cache_start_offset) {
        self->current_offset = new_offset;
    } else {
        rc = lseek(self->fd, new_offset, SEEK_SET);
        if (-1 == rc) {
            return -1;
        }

        self->current_offset = new_offset;
    }

    return self->current_offset;
}

int cached_file__fill_cache(struct cached_file_s *self, size_t size)
{
    if (self->cache) {
        free(self->cache);
        self->cache = NULL;
    }

    if (size > MAX_CACHE_SIZE) {
        size = MAX_CACHE_SIZE;
    }
    
    self->cache = (char *) malloc(size);
    self->cache_size = size;
    if (NULL == self->cache) {
        return -1;
    }

    off_t current_offset = lseek(self->fd, 0, SEEK_CUR);
    size_t rc = read(self->fd, self->cache, size);
    if (rc != size) {
        if (self->cache) {
            free(self->cache);
            self->cache = NULL;
        }

        return -1;
    }

    self->cache_start_offset = current_offset;
    self->cache_end_offset = self->cache_start_offset + rc;
    return 0;
}


int cached_file__read(struct cached_file_s *self, void *buf, size_t count)
{
    size_t bytes_left_to_read = count;
    char *tmp_buf = (char *) buf;
    
    while (bytes_left_to_read) {
        if ((self->current_offset < self->cache_end_offset && self->cache) &&
            (self->current_offset >= self->cache_start_offset)) {
            size_t cache_read = MIN((size_t) self->cache_end_offset - self->current_offset, count);
            memcpy(tmp_buf, &self->cache[self->current_offset - self->cache_start_offset], cache_read);
            tmp_buf += cache_read;
            bytes_left_to_read -= cache_read;
            self->current_offset += cache_read;
        }

        if (!bytes_left_to_read) {
            break;
        }

        off_t rc;
        rc = lseek(self->fd, self->current_offset, SEEK_SET);
        if (-1 == rc || rc != self->current_offset) {
            return -1;
        }

        rc = read(self->fd, tmp_buf, bytes_left_to_read);
        if (rc > 0) {
            self->current_offset += rc;
            bytes_left_to_read -= rc;
        }

        if (rc == -1) {
            return -1;
        }

        if (rc == 0) {
            break;
        }
    }

    return count - bytes_left_to_read;
}

bool_t cached_file__is_open(struct cached_file_s *self)
{
    if (self->fd >= 0) {
        return TRUE;
    } else {
        return FALSE;
    }
}

void cached_file__init(struct cached_file_s *self)
{
    memset(self, 0, sizeof(*self));
    self->fd = -1;
}
