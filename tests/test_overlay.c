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
}
static void keep(struct probe *p) {
    uint8_t packet[VN_PACKET],plain[VN_FRAME]; struct vn_header h;

    int n=vn_seal(&p->session,"labnet",p->id.node,VN_KEEPALIVE,NULL,0,packet);
    assert(n>0&&vn_send(p->fd,packet,(size_t)n,&relay)==0);
    n=receive(p->fd,packet,500); assert(n>0);
    assert(vn_open(&p->session,"labnet",packet,(size_t)n,&h,plain)==0&&h.type==VN_KEEPALIVE);
}
int main(int argc, char **argv) {
    assert(argc==7&&sodium_init()>=0);
    assert(vn_endpoint(argv[1],&relay)==0&&vn_public_load(argv[2],relay_pk)==0); vn_node(relay_node,relay_pk);

    struct probe peers[3]={0},bad={0};
    assert(establish(&bad,argv[6],"labnet")==-1); assert(close(bad.fd)==0);
    assert(puts("PASS unauthorized identity rejected")>=0);
    assert(establish(&bad,argv[3],"wrongnet")==-1); assert(close(bad.fd)==0);
    assert(puts("PASS incorrect network rejected")>=0);

    for (unsigned i=0;i<3;i++) assert(establish(&peers[i],argv[i+3],"labnet")==0);

    const uint8_t a[6]={2,0,0,0,0,1}, b[6]={2,0,0,0,0,2}, c[6]={2,0,0,0,0,3};

    const uint8_t broadcast[6]={255,255,255,255,255,255}, unknown[6]={2,0,0,0,0,99}, multi[6]={1,0,0,0,0,1};
    uint8_t saved[VN_PACKET]; int saved_n=0;
    send_frame(&peers[0],broadcast,a,1,saved,&saved_n); expect(peers,6,1);
    assert(puts("PASS broadcast recipients B,C; no echo A; source A learned")>=0);
    assert(vn_send(peers[0].fd,saved,(size_t)saved_n,&relay)==0); expect(peers,0,1);
    assert(puts("PASS replay rejected on real relay")>=0);
    send_frame(&peers[1],a,b,2,NULL,NULL); expect(peers,1,2);
    send_frame(&peers[0],b,a,3,NULL,NULL); expect(peers,2,3);
    assert(puts("PASS bidirectional known unicast only learned destination")>=0);
    send_frame(&peers[0],unknown,a,4,NULL,NULL); expect(peers,6,4);
    assert(puts("PASS unknown unicast flooded to B,C only")>=0);
    send_frame(&peers[0],multi,a,5,NULL,NULL); expect(peers,6,5);
    assert(puts("PASS multicast flooded to B,C only")>=0);
    /* Move B's source MAC to C, then verify destination changes. */
    send_frame(&peers[2],a,b,6,NULL,NULL); expect(peers,1,6);
    send_frame(&peers[0],b,a,7,NULL,NULL); expect(peers,4,7);
    assert(puts("PASS MAC move B -> C updates learned destination")>=0);
    uint8_t frame[60]={0}; memcpy(frame,broadcast,6); memcpy(frame+6,a,6);

    int n=vn_seal(&peers[0].session,"labnet",peers[0].id.node,VN_DATA,frame,60,saved);
    assert(n>0); saved[n-1]^=1;
    assert(vn_send(peers[0].fd,saved,(size_t)n,&relay)==0); expect(peers,0,0);
    assert(puts("PASS tampered ciphertext rejected on real relay")>=0);
    impersonate(&peers[0],argv[6]);
    assert(puts("PASS claimed allowlisted identity without secret cannot confirm or evict active session")>=0);
    keep(&peers[0]); keep(&peers[1]); keep(&peers[2]);
    /* Malformed, truncated, oversized and invalid-version packets hit the live socket. */
    uint8_t junk[2000]={0};

    for (unsigned i=0;i<84;i++) assert(vn_send(peers[0].fd,junk,i,&relay)==0);
    assert(vn_send(peers[0].fd,junk,sizeof(junk),&relay)==0);
    n=vn_seal(&peers[0].session,"labnet",peers[0].id.node,VN_KEEPALIVE,NULL,0,saved);
    assert(n>0); saved[4]=99; assert(vn_send(peers[0].fd,saved,(size_t)n,&relay)==0);
    expect(peers,0,0); keep(&peers[0]);
    assert(puts("PASS malformed/truncated/oversized/version packets rejected; relay still live")>=0);
    /* Keep sessions alive while all MACs exceed the configured 2-second age. */

    for (unsigned j=0;j<4;j++) { assert(sleep(1)==0); for (unsigned i=0;i<3;i++) keep(&peers[i]); }
    send_frame(&peers[0],b,a,8,NULL,NULL); expect(peers,6,8);
    assert(puts("PASS aged MAC B is now unknown and floods")>=0);
    /* Test harness relay uses peer timeout 6, MAC age 2. Refresh C MAC via C,
     * then stop C and keep A/B alive until it expires. Logs prove MAC removal
     * in a second long-age relay phase run by the shell script. */
    send_frame(&peers[2],a,c,9,NULL,NULL); expect(peers,1,9);

    for (unsigned j=0;j<7;j++) { assert(sleep(1)==0); keep(&peers[0]); keep(&peers[1]); }
    send_frame(&peers[0],broadcast,a,10,NULL,NULL); expect(peers,2,10);
    assert(puts("PASS stopped C expires; broadcast reaches only B")>=0);
    /* Resume C's expired session: a valid old packet cannot reactivate it. */
    send_frame(&peers[2],broadcast,c,11,NULL,NULL); expect(peers,0,11);
    assert(puts("PASS expired session cannot inject frames")>=0);

    for (unsigned i=0;i<3;i++) { assert(close(peers[i].fd)==0); sodium_memzero(&peers[i],sizeof(peers[i])); }
    sodium_memzero(&bad,sizeof(bad)); return 0;
}
