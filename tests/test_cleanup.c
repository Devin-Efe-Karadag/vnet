#include "vnet_util.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
/* Link-time fault injection affects only this test executable. */
int __real_close(int fd);
int __wrap_close(int fd);
int __wrap_unlink(const char *path);
static int calls;
int __wrap_close(int fd) {
    calls++; assert(__real_close(fd)==0); errno=EIO; return -1;
}
int __wrap_unlink(const char *path) {
    assert(path); calls++; errno=EACCES; return -1;
}
int main(void) {
    int fd=open("/dev/null",O_RDONLY|O_CLOEXEC); assert(fd>=0);
    errno=ENOSPC; vn_cleanup_close(fd); assert(errno==ENOSPC&&calls==1);
    errno=ENOSPC; vn_cleanup_unlink("test-only"); assert(errno==ENOSPC&&calls==2);
    assert(puts("PASS injected close/unlink failures reported; original errno preserved; close not retried")>=0);

    return 0;
}
