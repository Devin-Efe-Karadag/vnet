#include "vnet_netlink.h"
#include "vnet_util.h"
#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
static int transact(struct mnl_socket *s, struct nlmsghdr *h) {
    _Alignas(struct nlmsghdr) char reply[8192];

    if (mnl_socket_sendto(s,h,h->nlmsg_len)<0) return -1;

    for (;;) {
        ssize_t n=mnl_socket_recvfrom(s,reply,sizeof(reply));

        if (n<0&&errno==EINTR) continue;

        if (n<=0) return -1;

        int r=mnl_cb_run(reply,(size_t)n,h->nlmsg_seq,mnl_socket_get_portid(s),NULL,NULL);

        if (r<=MNL_CB_STOP) return r<0?-1:0;
    }
}
int vn_netlink_configure(const char *name, const char *cidr, unsigned mtu) {
    unsigned index=if_nametoindex(name); char address[64];

    if (!index||strlen(cidr)>=sizeof(address)) return -1;
    strcpy(address,cidr); char *slash=strchr(address,'/'), *end;

    if (!slash) { errno=EINVAL; return -1; }
    *slash++=0; errno=0; unsigned long prefix=strtoul(slash,&end,10);

    struct in_addr ip;

    if (errno||!*slash||*end||prefix>32||inet_pton(AF_INET,address,&ip)!=1) { errno=EINVAL; return -1; }

    struct mnl_socket *s=mnl_socket_open(NETLINK_ROUTE);

    if (!s) return -1;

    int r=-1;

    if (mnl_socket_bind(s,0,MNL_SOCKET_AUTOPID)<0) goto out;

    struct timeval timeout={.tv_sec=3};

    if (setsockopt(mnl_socket_get_fd(s),SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))<0) goto out;
    _Alignas(struct nlmsghdr) char buf[8192]={0};

    struct nlmsghdr *h=mnl_nlmsg_put_header(buf);
    h->nlmsg_type=RTM_NEWLINK; h->nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK; h->nlmsg_seq=1;

    struct ifinfomsg *link=mnl_nlmsg_put_extra_header(h,sizeof(*link));
    link->ifi_family=AF_UNSPEC; link->ifi_index=(int)index;
    link->ifi_flags=IFF_UP; link->ifi_change=IFF_UP;
    mnl_attr_put_u32(h,IFLA_MTU,mtu);

    if (transact(s,h)) goto out;
    memset(buf,0,sizeof(buf)); h=mnl_nlmsg_put_header(buf);
    h->nlmsg_type=RTM_NEWADDR; h->nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL; h->nlmsg_seq=2;

    struct ifaddrmsg *a=mnl_nlmsg_put_extra_header(h,sizeof(*a));
    a->ifa_family=AF_INET; a->ifa_prefixlen=(uint8_t)prefix; a->ifa_scope=RT_SCOPE_UNIVERSE; a->ifa_index=index;
    mnl_attr_put(h,IFA_LOCAL,sizeof(ip),&ip); mnl_attr_put(h,IFA_ADDRESS,sizeof(ip),&ip);
    r=transact(s,h);

    if (r&&errno==EEXIST) r=0;
out:
    {
        int e=errno;

        if (mnl_socket_close(s)<0) {
            int close_error=errno;
            vn_log("netlink close failed: %s",strerror(close_error));

            if (r==0) { r=-1; e=close_error; }
        }
        errno=e;
    }

    return r;
}
