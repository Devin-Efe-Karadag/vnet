#ifndef VNET_PROTOCOL_H
#define VNET_PROTOCOL_H
#include <stddef.h>
#include <stdint.h>
/* Serialized manually: never transmit a C structure.
 * 0 magic(4), 4 version(1), 5 type(1), 6 flags(2), 8 network(32),
 * 40 sender node(16), 56 session(16), 72 sequence(8), 80 payload length(2),
 * 82 reserved(2). Integers big endian; strings NUL padded.
 * AEAD nonce = direction[1] || session[0..14] || wire sequence[8].
 * Direction 0 is client-to-relay, 1 relay-to-client; entire header is AD.
 */
#define VN_HEADER 84u
#define VN_TAG 16u
#define VN_MTU 1300u
#define VN_MAX_MTU 1400u
#define VN_FRAME (VN_MAX_MTU + 14u)
#define VN_PACKET (VN_HEADER + VN_FRAME + VN_TAG)
#define VN_PEERS 64u
#define VN_MACS 1024u
#define VN_VERSION 2u
enum vn_type { VN_HELLO=1, VN_WELCOME, VN_CONFIRM, VN_DATA,
               VN_KEEPALIVE, VN_GOODBYE, VN_ERROR };
struct vn_header {
    uint8_t type, node[16], sid[16];
    uint64_t seq;
    uint16_t len;
};
int vn_network_valid(const char *network);
void vn_header_write(uint8_t *out, const char *network, const struct vn_header *h);
int vn_header_read(struct vn_header *h, const uint8_t *in, size_t n, const char *network);
uint64_t vn_get64(const uint8_t *p);
void vn_put64(uint8_t *p, uint64_t x);
#endif
