#ifndef VNET_CRYPTO_H
#define VNET_CRYPTO_H
#include "vnet_protocol.h"
struct vn_identity { uint8_t pk[32], sk[32], node[16]; };
struct vn_session {
    uint8_t sid[16], rx[32], tx[32];
    uint8_t rx_prefix[16], tx_prefix[16];
    uint64_t sent, highest, window;

    int ready;
};
int vn_identity_load(const char *path, struct vn_identity *id, int create);
int vn_public_load(const char *path, uint8_t pk[32]);
void vn_node(uint8_t node[16], const uint8_t pk[32]);
int vn_derive(struct vn_session *s, const struct vn_identity *id,
              const uint8_t other[32], const uint8_t challenge[32],

              const uint8_t sid[16], const char *network, int server);
int vn_seal(struct vn_session *s, const char *network, const uint8_t sender[16],
            uint8_t type, const uint8_t *plain, size_t n, uint8_t *out);
/* Returns plaintext length; -2 denotes duplicate/stale, -1 any other error.
 * Replay state is modified only after successful authentication. */
int vn_open(struct vn_session *s, const char *network, const uint8_t *packet,
            size_t n, struct vn_header *h, uint8_t *plain);
#endif
