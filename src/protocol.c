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
