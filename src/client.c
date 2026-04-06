#include "vnet_util.h"
#include "vnet_tap.h"
#include "vnet_netlink.h"
#include <sodium.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
struct client {
    struct vn_options o; struct vn_identity id; struct vn_session session;
    uint8_t relay_pk[32],relay_node[16],challenge[32];

    struct sockaddr_in server;

    int udp,tap,active;
    uint64_t seen,started,rx,tx,drops;
    c->active=0; c->started=vn_now(); vn_log("connecting server=%s",c->o.endpoint);
}
static void send_encrypted(struct client *c, uint8_t type, const uint8_t *data, size_t size) {
    uint8_t packet[VN_PACKET]; int n=vn_seal(&c->session,c->o.network,c->id.node,type,data,size,packet);

    if (n<0) { reset(c); return; }
