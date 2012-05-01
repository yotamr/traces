#ifndef __FILESYSTEM_H__
#define __FILESYSTEM_H__

int get_file_size(const char *filename);
long long free_bytes_in_fs(const char *mnt);

#endif
