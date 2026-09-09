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

    while (milliseconds()<deadline) {
        struct pollfd pollers[3];

        for (unsigned i=0;i<3;i++) pollers[i]=(struct pollfd){.fd=ports[i].fd,.events=POLLIN};

        int left=(int)(deadline-milliseconds()); if (left<=0) break;

        int count=poll(pollers,3,left); if (count<0&&errno==EINTR) continue;
        assert(count>=0);

        for (unsigned i=0;i<3;i++) if (pollers[i].revents&POLLIN) {
            uint8_t bytes[2000]; struct sockaddr_ll from; socklen_t size=sizeof(from);

            ssize_t n=recvfrom(ports[i].fd,bytes,sizeof(bytes),0,(struct sockaddr *)&from,&size);
            assert(n>=0);
            /* Ignore the locally injected outgoing copy, never an incoming echo. */

            if (from.sll_pkttype==PACKET_OUTGOING||n<21||bytes[12]!=0x88||bytes[13]!=0xb5||memcmp(bytes+14,"VNTEST",6)) continue;
            assert(bytes[20]==marker); received[i]++;
        }
    }

    for (unsigned i=0;i<3;i++) {
        unsigned want=(mask>>i)&1u;

        if (received[i]!=want) {
            if (fprintf(stderr,"marker=%u namespace=%c expected=%u received=%u\n",marker,'a'+i,want,received[i])<0) _exit(1);
        }
        assert(received[i]==want);
    }
}
static void arm(int control, char mode, char direction) {
    char command[2]={mode,direction},reply[2];
    assert(send(control,command,2,MSG_NOSIGNAL)==2);

    struct pollfd p={.fd=control,.events=POLLIN}; assert(poll(&p,1,1000)==1);
    assert(recv(control,reply,2,0)==2&&!memcmp(command,reply,2));
}
static void pass(const char *message) { assert(puts(message)>=0&&fflush(stdout)==0); }
int main(int argc, char **argv) {
    assert(argc==3);

    int original=open("/proc/self/ns/net",O_RDONLY|O_CLOEXEC); assert(original>=0);

    struct port ports[3]; for (unsigned i=0;i<3;i++) ports[i]=open_port((char)('a'+i),original);
    assert(close(original)==0);

    int control=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0); assert(control>=0);

    struct sockaddr_un addr={.sun_family=AF_UNIX}; assert(strlen(argv[1])<sizeof(addr.sun_path)); strcpy(addr.sun_path,argv[1]);
    assert(connect(control,(struct sockaddr *)&addr,sizeof(addr))==0);

    if (!strcmp(argv[2],"forward")) {
        const uint8_t unknown[6]={2,0,0,0,0,99},group[6]={1,0,0,0,0,1};
        frame(&ports[0],broadcast,a,1,60); expect(ports,6,1);
        pass("PASS namespace TAP broadcast reaches B,C once; no incoming echo on A");
        frame(&ports[1],a,b,2,60); expect(ports,1,2);
        frame(&ports[0],b,a,3,60); expect(ports,2,3);
        pass("PASS namespace TAP known unicast only reaches learned destination");
        frame(&ports[0],unknown,a,4,60); expect(ports,6,4);
        frame(&ports[0],group,a,5,60); expect(ports,6,5);
        pass("PASS namespace TAP unknown unicast and multicast flood only to B,C");
        frame(&ports[2],a,b,6,60); expect(ports,1,6);
        frame(&ports[0],b,a,7,60); expect(ports,4,7);
        pass("PASS namespace TAP source learning and MAC move B -> C");
        uint8_t marker=20;

        for (const char *mode="RTNVLOUS";*mode;mode++) {
            arm(control,*mode,'u'); frame(&ports[0],broadcast,a,marker,60);
            expect(ports,*mode=='R'?6:0,marker++);
            /* A fresh frame must still traverse the real TAP/AEAD path. */
            frame(&ports[0],broadcast,a,marker,60); expect(ports,6,marker++);
        }
        pass("PASS namespace TAP uplink replay delivered once; tamper/network/version/truncation/oversize/node/session mutations rejected");

        for (const char *mode="RTNVLOS";*mode;mode++) {
            arm(control,*mode,'d'); frame(&ports[1],a,b,marker,60);
            expect(ports,*mode=='R'?1:0,marker++);
            frame(&ports[1],a,b,marker,60); expect(ports,1,marker++);
        }
        pass("PASS namespace TAP downlink replay delivered once; tamper/network/version/truncation/oversize/session mutations rejected");
    } else if (!strcmp(argv[2],"age")) {
        frame(&ports[0],broadcast,a,100,60); expect(ports,6,100);
        frame(&ports[1],a,b,101,60); expect(ports,1,101);
        frame(&ports[0],b,a,102,60); expect(ports,2,102);

        struct timespec wait={.tv_sec=4}; assert(nanosleep(&wait,NULL)==0);
        frame(&ports[0],b,a,103,60); expect(ports,6,103);
        pass("PASS namespace TAP MAC ages while real clients keep sessions alive; old unicast now floods");
    } else if (!strcmp(argv[2],"relay-error")) {
        const uint8_t invalid[6]={1,0,0,0,0,1};
        frame(&ports[0],broadcast,invalid,110,60); expect(ports,0,110);
        pass("PASS namespace TAP authenticated invalid source not forwarded; relay ERROR checked by script");
    } else if (!strcmp(argv[2],"client-error")) {
        /* C deliberately runs MTU 1200 in this negative test. */
        frame(&ports[0],broadcast,a,111,60); expect(ports,6,111);
        frame(&ports[2],a,c,112,60); expect(ports,1,112);
        frame(&ports[0],c,a,113,1250); expect(ports,0,113);
        pass("PASS namespace TAP authenticated oversized downlink not injected; client ERROR checked by script");
    } else assert(0);
    assert(close(control)==0);

    for (unsigned i=0;i<3;i++) assert(close(ports[i].fd)==0);

    return 0;
}
