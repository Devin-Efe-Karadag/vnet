#include "vnet_switch.h"
#include <string.h>
int vn_peer_find(const struct vn_peer *peers, size_t count, const uint8_t node[16]) {
