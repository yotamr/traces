#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

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
