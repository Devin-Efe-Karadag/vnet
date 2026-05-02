#include "vnet_protocol.h"
#include <string.h>
uint64_t vn_get64(const uint8_t *p) {
    uint64_t x=0;

    for (unsigned i=0;i<8;i++) x=(x<<8)|p[i];

    return x;
}
void vn_put64(uint8_t *p, uint64_t x) {
    for (unsigned i=8;i>0;i--) { p[i-1]=(uint8_t)x; x>>=8; }
}
int vn_network_valid(const char *s) {
    size_t n=strlen(s);

    if (!n || n>31) return 0;

    for (size_t i=0;i<n;i++)
        if (!((s[i]>='a'&&s[i]<='z')||(s[i]>='A'&&s[i]<='Z')||
              (s[i]>='0'&&s[i]<='9')||s[i]=='-'||s[i]=='_')) return 0;
    return 1;
}
void vn_header_write(uint8_t *out, const char *network, const struct vn_header *h) {
    memset(out,0,VN_HEADER); memcpy(out,"VNET",4);
    out[4]=VN_VERSION; out[5]=h->type;
    memcpy(out+8,network,strlen(network)); memcpy(out+40,h->node,16);
    memcpy(out+56,h->sid,16); vn_put64(out+72,h->seq);
    out[80]=(uint8_t)(h->len>>8); out[81]=(uint8_t)h->len;
}
int vn_header_read(struct vn_header *h, const uint8_t *in, size_t n, const char *network) {
    uint8_t net[32]={0};

    if (!vn_network_valid(network)||n<VN_HEADER||n>VN_PACKET) return -1;
    memcpy(net,network,strlen(network));

    if (memcmp(in,"VNET",4)||in[4]!=VN_VERSION||in[5]<VN_HELLO||in[5]>VN_ERROR||
        in[6]||in[7]||in[82]||in[83]||memcmp(net,in+8,32)) return -1;
    h->type=in[5]; memcpy(h->node,in+40,16); memcpy(h->sid,in+56,16);
    h->seq=vn_get64(in+72); h->len=(uint16_t)(((unsigned)in[80]<<8)|in[81]);

    if (n!=VN_HEADER+h->len) return -1;

    if (h->type==VN_HELLO||h->type==VN_WELCOME) {
        uint8_t zero[16]={0};

        if (h->len!=64||h->seq!=0) return -1;

        if ((h->type==VN_HELLO)==(memcmp(h->sid,zero,16)!=0)) return -1;
    } else {
        if (!h->seq||h->len<VN_TAG||h->len>VN_FRAME+VN_TAG) return -1;

        if (h->type!=VN_DATA&&h->len!=VN_TAG) return -1;

        if (h->type==VN_DATA&&h->len<14+VN_TAG) return -1;
    }

    return 0;
}
