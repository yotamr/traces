#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/vfs.h>

long long get_file_size(const char *filename)
{
    struct stat st;
    int rc = stat(filename, &st);
    
    if (0 != rc) {
        return -1;
    } else {
        return st.st_size;
    }
}

long long free_bytes_in_fs(const char *mnt)
{
    struct statfs vfs;
    int rc = statfs(mnt, &vfs);
    if (0 != rc) {
        return -1;
    }

    return vfs.f_bsize * vfs.f_bfree;
}
