#include "vnet_switch.h"
#include <sodium.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
struct relay {
    struct vn_options o;

    struct vn_identity id;

    struct vn_peer peers[VN_PEERS]; size_t count;

    struct vn_mac macs[VN_MACS];

    int udp;
    uint64_t rejected, replay, bad_tag, floods, unicasts, send_drop;
};
    vn_log("peer_expire peer=%u reason=%s",index,reason);
}
static void send_encrypted(struct relay *r, unsigned index, uint8_t type, const uint8_t *data, size_t n) {
    struct vn_peer *p=&r->peers[index]; uint8_t packet[VN_PACKET];

    int len=vn_seal(&p->session,r->o.network,r->id.node,type,data,n,packet);

    if (len<0) { expire(r,index,"sequence-exhausted"); return; }
    }

    if (!p->active||!vn_same_endpoint(from,&p->endpoint)||memcmp(h.sid,p->session.sid,16)||h.type<VN_CONFIRM) {
        r->rejected++; p->drops++; return;
    }
        }
        vn_mac_learn(r->macs,plain+6,(unsigned)index,p->seen);

        int dest=(plain[0]&1)?-1:vn_mac_find(r->macs,plain);
