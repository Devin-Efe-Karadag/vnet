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
        if (count<0) { if (errno==EINTR) continue; perror("epoll_wait"); goto out; }

        for (int i=0;i<count;i++) {
            int fd=events[i].data.fd;

            if (fd==r.udp) {
                /* Budget prevents an always-readable socket starving timers/signals. */

                for (unsigned budget=0;budget<64;budget++) {
                    uint8_t packet[VN_PACKET]; struct sockaddr_in from; socklen_t size=sizeof(from);

                    ssize_t n=recvfrom(fd,packet,sizeof(packet),MSG_TRUNC,(struct sockaddr *)&from,&size);

                    if (n<0) { if (errno==EINTR) continue; if (errno==EAGAIN||errno==EWOULDBLOCK) break; perror("recvfrom"); goto out; }

                    if (size!=sizeof(from)||(size_t)n>sizeof(packet)) r.rejected++;
                    else receive_packet(&r,packet,(size_t)n,&from);
                }
            } else if (fd==timer) {
                uint64_t ticks; ssize_t n=read(timer,&ticks,sizeof(ticks));

                if (n<0&&errno==EAGAIN) continue;

                if (n!=sizeof(ticks)) { perror("timer read"); goto out; }
                uint64_t now=vn_now();

                for (size_t j=0;j<r.count;j++) {
                    struct vn_peer *p=&r.peers[j];
                    if (p->pending.ready&&now-p->pending_since>=r.o.peer_timeout)
                }
                if (now%5==0) status(&r);
                struct signalfd_siginfo sig; ssize_t n=read(fd,&sig,sizeof(sig));
                if (n!=sizeof(sig)) { perror("signal read"); goto out; }
            }
    }
    status(&r); result=0;
    if (ep>=0&&close(ep)<0) result=1;
    if (signals>=0&&close(signals)<0) result=1;
    sodium_memzero(&r,sizeof(r)); return result;
