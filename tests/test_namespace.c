/* Sends and captures actual Ethernet frames on vnet0 in each namespace.
 * No identity/session keys: all encryption is performed by vnet-client. */
#include "vnet_util.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/un.h>
struct port { int fd; unsigned index; };
static const uint8_t a[6]={2,0,0,0,0,1},b[6]={2,0,0,0,0,2},c[6]={2,0,0,0,0,3};
static const uint8_t broadcast[6]={255,255,255,255,255,255};
static long long milliseconds(void) {
    struct timespec t; assert(clock_gettime(CLOCK_MONOTONIC,&t)==0);

    return (long long)t.tv_sec*1000+t.tv_nsec/1000000;
}
static struct port open_port(char letter, int original) {
    char path[64]; int n=snprintf(path,sizeof(path),"/var/run/netns/vnet-%c",letter);
    assert(n>0&&(size_t)n<sizeof(path));

    int ns=open(path,O_RDONLY|O_CLOEXEC); assert(ns>=0&&setns(ns,CLONE_NEWNET)==0);

    struct port p={.fd=socket(AF_PACKET,SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC,htons(ETH_P_ALL))};
    p.index=if_nametoindex("vnet0"); assert(p.fd>=0&&p.index);

    struct sockaddr_ll addr={.sll_family=AF_PACKET,.sll_protocol=htons(ETH_P_ALL),.sll_ifindex=(int)p.index};
    assert(bind(p.fd,(struct sockaddr *)&addr,sizeof(addr))==0);

    struct packet_mreq member={.mr_ifindex=(int)p.index,.mr_type=PACKET_MR_PROMISC};
    assert(setsockopt(p.fd,SOL_PACKET,PACKET_ADD_MEMBERSHIP,&member,sizeof(member))==0);
    assert(setns(original,CLONE_NEWNET)==0&&close(ns)==0); return p;
}
static void frame(const struct port *p, const uint8_t *dest, const uint8_t *src, uint8_t marker, size_t n) {
    uint8_t bytes[VN_FRAME]={0}; assert(n>=60&&n<=sizeof(bytes));
    memcpy(bytes,dest,6); memcpy(bytes+6,src,6); bytes[12]=0x88; bytes[13]=0xb5;
    memcpy(bytes+14,"VNTEST",6); bytes[20]=marker;

    struct sockaddr_ll to={.sll_family=AF_PACKET,.sll_ifindex=(int)p->index,.sll_halen=6};
    memcpy(to.sll_addr,dest,6);
    assert(sendto(p->fd,bytes,n,0,(struct sockaddr *)&to,sizeof(to))==(ssize_t)n);
}
static void expect(struct port ports[3], unsigned mask, uint8_t marker) {
    unsigned received[3]={0}; long long deadline=milliseconds()+300;
