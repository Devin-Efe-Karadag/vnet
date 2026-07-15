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
