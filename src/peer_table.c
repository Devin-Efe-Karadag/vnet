#include "vnet_switch.h"
#include <string.h>
int vn_peer_find(const struct vn_peer *peers, size_t count, const uint8_t node[16]) {
    for (size_t i=0;i<count;i++) if (!memcmp(peers[i].node,node,16)) return (int)i;

    return -1;
