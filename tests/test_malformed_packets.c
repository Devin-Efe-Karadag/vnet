#include "vnet_protocol.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sodium.h>
int main(void) {
    assert(sodium_init()>=0);
    uint8_t data[VN_PACKET+1]={0}; struct vn_header h={.type=VN_HELLO,.len=64},got;
    vn_header_write(data,"labnet",&h);
    assert(vn_header_read(&got,data,VN_HEADER+64,"labnet")==0);

    for (size_t n=0;n<VN_HEADER+64;n++) assert(vn_header_read(&got,data,n,"labnet")==-1);
    assert(vn_header_read(&got,data,sizeof(data),"labnet")==-1);

    const unsigned offsets[]={0,4,6,7,8,39,56,72,80,81,82,83};

    for (unsigned i=0;i<sizeof(offsets)/sizeof(offsets[0]);i++) {
        data[offsets[i]]^=128; assert(vn_header_read(&got,data,VN_HEADER+64,"labnet")==-1); data[offsets[i]]^=128;
    }
    data[5]=255; assert(vn_header_read(&got,data,VN_HEADER+64,"labnet")==-1);
    assert(vn_header_read(&got,data,VN_HEADER+64,"abcdefghijklmnopqrstuvwxyz012345")==-1);

    for (unsigned i=0;i<50000;i++) {
        size_t n=randombytes_uniform(sizeof(data)+1); randombytes_buf(data,n);

        int r=vn_header_read(&got,data,n,"labnet"); assert(r==0||r==-1);
    }
    assert(puts("PASS malformed: all HELLO truncations, oversize, fixed-field mutations, unsupported types, 50000 bounded random datagrams")>=0);

    return 0;
}
