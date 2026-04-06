#ifndef VNET_SWITCH_H
#define VNET_SWITCH_H
#include "vnet_util.h"
struct vn_peer {
    uint8_t node[16], pk[32], challenge[32];

    struct vn_session session, pending;

    struct sockaddr_in endpoint, pending_endpoint;
    uint64_t seen, pending_since, rx, tx, drops;

    int active;
};
struct vn_mac { uint8_t addr[6]; int used; unsigned peer; uint64_t seen; };
int vn_allowlist(const char *path, struct vn_peer peers[VN_PEERS], size_t *count);
int vn_peer_find(const struct vn_peer *peers, size_t count, const uint8_t node[16]);
void vn_mac_remove_peer(struct vn_mac *table, unsigned peer);
void vn_mac_age(struct vn_mac *table, uint64_t now, unsigned age);
void vn_mac_learn(struct vn_mac *table, const uint8_t *mac, unsigned peer, uint64_t now);
int vn_mac_find(const struct vn_mac *table, const uint8_t *mac);
#endif
