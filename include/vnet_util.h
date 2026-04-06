#ifndef VNET_UTIL_H
#define VNET_UTIL_H
#include <netinet/in.h>
#include <stdint.h>
#include "vnet_crypto.h"
struct vn_options {
    const char *endpoint, *network, *identity, *allowlist, *relay_key;

    const char *interface, *address;

    unsigned mtu, peer_timeout, mac_age;
};
uint64_t vn_now(void);
/* Report cleanup failures while preserving errno from the original failure.
 * Never retry close on Linux: even EINTR can mean the descriptor is released. */
void vn_cleanup_close(int fd);
void vn_cleanup_unlink(const char *path);
void vn_log(const char *fmt, ...) __attribute__((format(printf,1,2)));
int vn_endpoint(const char *text, struct sockaddr_in *addr);
int vn_udp(const struct sockaddr_in *bind_addr);
int vn_same_endpoint(const struct sockaddr_in *a, const struct sockaddr_in *b);
int vn_epoll_add(int ep, int fd);
int vn_events(int *timer, int *signals);
int vn_send(int fd, const void *buf, size_t n, const struct sockaddr_in *to);
int vn_options_parse(int argc, char **argv, struct vn_options *o, int server);
void vn_hex(char *out, const uint8_t *in, size_t n);
int vn_unhex(uint8_t *out, size_t n, const char *in);
#endif
