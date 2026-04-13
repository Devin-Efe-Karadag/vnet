#include "vnet_tap.h"
#include "vnet_util.h"
#include <linux/if_tun.h>
#include <net/if.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
int vn_tap_open(const char *name) {
    if (!*name||strlen(name)>=IFNAMSIZ||strchr(name,'%')) { errno=EINVAL; return -1; }

    int fd=open("/dev/net/tun",O_RDWR|O_NONBLOCK|O_CLOEXEC);

    if (fd<0) return -1;

    struct ifreq req={0}; req.ifr_flags=IFF_TAP|IFF_NO_PI;
    memcpy(req.ifr_name,name,strlen(name)+1);

    if (ioctl(fd,TUNSETIFF,&req)<0) { int e=errno; vn_cleanup_close(fd); errno=e; return -1; }

    return fd;
}
