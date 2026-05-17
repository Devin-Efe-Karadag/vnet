#include "vnet_switch.h"
#include <sodium.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
static void identity(struct vn_identity *id) {
    assert(crypto_kx_keypair(id->pk,id->sk)==0); vn_node(id->node,id->pk);
}
int main(void) {
    assert(sodium_init()>=0);

    struct vn_identity a,b; identity(&a); identity(&b);
    uint8_t challenge[32],sid[16],packet[VN_PACKET],saved[VN_PACKET],plain[VN_FRAME];
    randombytes_buf(challenge,32); randombytes_buf(sid,16);

    struct vn_session client,server;
    assert(vn_derive(&client,&a,b.pk,challenge,sid,"labnet",0)==0);
    assert(vn_derive(&server,&b,a.pk,challenge,sid,"labnet",1)==0);
    assert(!memcmp(client.tx,server.rx,32)); assert(!memcmp(client.rx,server.tx,32));
    assert(memcmp(client.tx,client.rx,32));
    assert(!memcmp(client.tx_prefix,server.rx_prefix,16));
    assert(!memcmp(client.rx_prefix,server.tx_prefix,16));
    assert(memcmp(client.tx_prefix,client.rx_prefix,16));
    assert(client.tx_prefix[0]==0&&server.tx_prefix[0]==1);
    uint8_t up_nonce[24],down_nonce[24];
    memcpy(up_nonce,client.tx_prefix,16); memcpy(down_nonce,server.tx_prefix,16);
    vn_put64(up_nonce+16,1); vn_put64(down_nonce+16,1);
    assert(memcmp(up_nonce,down_nonce,sizeof(up_nonce)));

    struct vn_header h;

    int n=vn_seal(&client,"labnet",a.node,VN_CONFIRM,NULL,0,packet);
    assert(n==(int)(VN_HEADER+VN_TAG));
    assert(!memcmp(packet,"VNET\2\3\0\0labnet",14));
    assert(packet[79]==1&&packet[80]==0&&packet[81]==16);
    assert(vn_open(&server,"labnet",packet,(size_t)n,&h,plain)==0);
    assert(vn_open(&server,"labnet",packet,(size_t)n,&h,plain)==-2);
    n=vn_seal(&server,"labnet",b.node,VN_CONFIRM,NULL,0,packet);
    assert(vn_open(&client,"labnet",packet,(size_t)n,&h,plain)==0);
    n=vn_seal(&client,"labnet",a.node,VN_ERROR,NULL,0,packet);
    memcpy(saved,packet,(size_t)n); saved[n-1]^=1;
    assert(vn_open(&server,"labnet",saved,(size_t)n,&h,plain)==-1);
    assert(server.highest==1);
    assert(vn_open(&server,"labnet",packet,(size_t)n,&h,plain)==0&&h.type==VN_ERROR);
    n=vn_seal(&server,"labnet",b.node,VN_ERROR,NULL,0,packet);
    assert(vn_open(&client,"labnet",packet,(size_t)n,&h,plain)==0&&h.type==VN_ERROR);
    uint8_t frame[60]={0}; memset(frame,255,6); frame[6]=2; frame[12]=8;
    n=vn_seal(&client,"labnet",a.node,VN_DATA,frame,sizeof(frame),packet);
    memcpy(saved,packet,(size_t)n); packet[n-1]^=1;
    assert(vn_open(&server,"labnet",packet,(size_t)n,&h,plain)==-1);
    assert(server.highest==2); /* invalid tags cannot advance replay state */
    memcpy(packet,saved,(size_t)n); packet[79]=100;
    assert(vn_open(&server,"labnet",packet,(size_t)n,&h,plain)==-1);
    assert(server.highest==2); /* forged high sequence is authenticated AD */
    assert(!memcmp(plain,frame,60));
    int old_n=vn_seal(&client,"labnet",a.node,VN_KEEPALIVE,NULL,0,saved);
    assert(vn_open(&server,"labnet",packet,(size_t)n,&h,plain)==0);
    old_n=vn_seal(&client,"labnet",a.node,VN_KEEPALIVE,NULL,0,saved);
    n=vn_seal(&client,"labnet",a.node,VN_KEEPALIVE,NULL,0,packet);
    assert(vn_open(&server,"labnet",saved,(size_t)old_n,&h,plain)==-2);
    struct vn_session other;
    assert(vn_derive(&other,&a,b.pk,challenge,sid,"labnet",0)==0);
    client.sent=UINT64_MAX;
    uint8_t zero[32]={0}; assert(vn_derive(&other,&a,zero,challenge,sid,"labnet",0)==-1);
    vn_mac_learn(table,mac,0,100); assert(vn_mac_find(table,mac)==0);
    vn_mac_age(table,102,2); assert(vn_mac_find(table,mac)==1);
    vn_mac_learn(table,mac,2,104); vn_mac_remove_peer(table,2); assert(vn_mac_find(table,mac)==-1);
    for (unsigned i=0;i<VN_MACS;i++) { table[i].used=1; table[i].seen=100+i; table[i].addr[0]=4; }
    sodium_memzero(&a,sizeof(a)); sodium_memzero(&b,sizeof(b));
    assert(puts("PASS protocol: wire offsets, directional keys/nonces, bidirectional ERROR, AEAD, tamper, replay/reorder/stale, session binding, wrap, MAC move/aging/replacement")>=0);
}
