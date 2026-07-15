/* Deterministic Ethernet/hostile-wire probes against the real UDP relay.
 * Independent sockets let the test assert each recipient and no echo. */
#include "vnet_util.h"
#include <sodium.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <stdlib.h>
struct probe { int fd; struct vn_identity id; struct vn_session session; };
static struct sockaddr_in relay;
static uint8_t relay_pk[32],relay_node[16];
static int receive(int fd, uint8_t *data, int timeout) {
    struct pollfd p={.fd=fd,.events=POLLIN}; int r=poll(&p,1,timeout);
    assert(r>=0); if (!r) return 0;

    ssize_t n=recv(fd,data,VN_PACKET,0); assert(n>0); return (int)n;
}
static int establish(struct probe *p, const char *path, const char *network) {
    p->fd=vn_udp(NULL); assert(p->fd>=0);
    assert(vn_identity_load(path,&p->id,0)==0);
    uint8_t challenge[32],packet[VN_PACKET],plain[VN_FRAME]; randombytes_buf(challenge,32);

    struct vn_header h={.type=VN_HELLO,.len=64}; memcpy(h.node,p->id.node,16);
    vn_header_write(packet,network,&h); memcpy(packet+VN_HEADER,p->id.pk,32); memcpy(packet+VN_HEADER+32,challenge,32);
    assert(vn_send(p->fd,packet,VN_HEADER+64,&relay)==0);

    int n=receive(p->fd,packet,500); if (!n) return -1;
    assert(vn_header_read(&h,packet,(size_t)n,network)==0&&h.type==VN_WELCOME);
    assert(!memcmp(h.node,relay_node,16)&&!memcmp(packet+VN_HEADER,relay_pk,32)&&!memcmp(packet+VN_HEADER+32,challenge,32));
    assert(vn_derive(&p->session,&p->id,relay_pk,challenge,h.sid,network,0)==0);
    n=vn_seal(&p->session,network,p->id.node,VN_CONFIRM,NULL,0,packet);
    assert(n>0&&vn_send(p->fd,packet,(size_t)n,&relay)==0);
    n=receive(p->fd,packet,500); assert(n>0);
    assert(vn_open(&p->session,network,packet,(size_t)n,&h,plain)==0&&h.type==VN_CONFIRM);

    return 0;
}
static void impersonate(const struct probe *victim, const char *outsider) {
    struct probe attacker={0};
    attacker.fd=vn_udp(NULL); assert(attacker.fd>=0);
    assert(vn_identity_load(outsider,&attacker.id,0)==0);
    uint8_t challenge[32],packet[VN_PACKET]; randombytes_buf(challenge,32);

    struct vn_header h={.type=VN_HELLO,.len=64}; memcpy(h.node,victim->id.node,16);
    vn_header_write(packet,"labnet",&h); memcpy(packet+VN_HEADER,victim->id.pk,32);
    memcpy(packet+VN_HEADER+32,challenge,32);
    assert(vn_send(attacker.fd,packet,VN_HEADER+64,&relay)==0);

    int n=receive(attacker.fd,packet,500); assert(n>0);
    assert(vn_header_read(&h,packet,(size_t)n,"labnet")==0&&h.type==VN_WELCOME);
    assert(vn_derive(&attacker.session,&attacker.id,relay_pk,challenge,h.sid,"labnet",0)==0);
    n=vn_seal(&attacker.session,"labnet",victim->id.node,VN_CONFIRM,NULL,0,packet);
    assert(n>0&&vn_send(attacker.fd,packet,(size_t)n,&relay)==0);
    assert(receive(attacker.fd,packet,200)==0);
    assert(close(attacker.fd)==0); sodium_memzero(&attacker,sizeof(attacker));
}
static void send_frame(struct probe *p, const uint8_t dest[6], const uint8_t src[6], uint8_t marker, uint8_t *saved, int *saved_n) {
    uint8_t frame[60]={0},packet[VN_PACKET]; memcpy(frame,dest,6); memcpy(frame+6,src,6);
    frame[12]=0x88; frame[13]=0xb5; frame[14]=marker;

    int n=vn_seal(&p->session,"labnet",p->id.node,VN_DATA,frame,sizeof(frame),packet);
    assert(n>0&&vn_send(p->fd,packet,(size_t)n,&relay)==0);

    if (saved) { memcpy(saved,packet,(size_t)n); *saved_n=n; }
}
static void expect(struct probe peers[3], unsigned mask, uint8_t marker) {
    for (unsigned i=0;i<3;i++) {
        uint8_t packet[VN_PACKET],plain[VN_FRAME]; struct vn_header h;

        int n=receive(peers[i].fd,packet,120);

        if (mask&(1u<<i)) {
            if (!n) assert(fprintf(stderr,"missing marker=%u peer=%u\n",marker,i)>=0);
            assert(n>0&&vn_open(&peers[i].session,"labnet",packet,(size_t)n,&h,plain)==60);
            assert(h.type==VN_DATA&&plain[14]==marker);
        } else { if (n) assert(fprintf(stderr,"unexpected marker=%u peer=%u\n",marker,i)>=0); assert(n==0); }
    }
