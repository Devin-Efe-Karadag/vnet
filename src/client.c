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
        if (written!=len) c->drops++;
        break;
    }
    default: c->drops++; break;
    }
}
int main(int argc, char **argv) {
    struct client c={.udp=-1,.tap=-1}; int ep=-1,timer=-1,signals=-1,result=1;

    if (vn_options_parse(argc,argv,&c.o,0)) {
        if (fprintf(stderr,"usage: %s --server IPv4:PORT --network-id NAME --identity FILE --relay-public-key FILE --interface NAME --address IPv4/PREFIX [--mtu 1300 --peer-timeout 30]\n",argv[0])<0) return 1;

        return 2;
    }

    if (sodium_init()<0) return 1;

    if (vn_endpoint(c.o.endpoint,&c.server)||vn_identity_load(c.o.identity,&c.id,1)||vn_public_load(c.o.relay_key,c.relay_pk)) {
        vn_log("invalid endpoint, identity, or relay public key"); goto out;
    }
    vn_node(c.relay_node,c.relay_pk); c.tap=vn_tap_open(c.o.interface);

    if (c.tap<0||vn_netlink_configure(c.o.interface,c.o.address,c.o.mtu)) { perror("TAP/netlink setup"); goto out; }
    c.udp=vn_udp(NULL); ep=vn_events(&timer,&signals);

    if (c.udp<0||ep<0||vn_epoll_add(ep,c.udp)<0||vn_epoll_add(ep,c.tap)<0) { perror("client setup"); goto out; }
                    } else {
                        n=read(fd,packet,sizeof(packet));

                        if (n>0) {
                            if (c.active&&n>=14&&(size_t)n<=c.o.mtu+14) send_encrypted(&c,VN_DATA,packet,(size_t)n);
                            else c.drops++;
                        }

                        if (n==0) { vn_log("TAP closed"); goto out; }
                    }

                    if (n<0) { if (errno==EINTR) continue; if (errno==EAGAIN||errno==EWOULDBLOCK) break; perror("client read"); goto out; }
                if ((c.active&&now-c.seen>=c.o.peer_timeout)||(!c.active&&now-c.started>=c.o.peer_timeout)) reset(&c);

                if (c.active) send_encrypted(&c,VN_KEEPALIVE,NULL,0); else handshake(&c);

                if (now%5==0) status(&c);
            } else if (fd==signals) {
                struct signalfd_siginfo sig; ssize_t n=read(fd,&sig,sizeof(sig));

                if (n<0&&errno==EAGAIN) continue;

                if (n!=sizeof(sig)) { perror("signal read"); goto out; }

                if (sig.ssi_signo==SIGUSR1) status(&c); else running=0;
            }
        }
    }

    if (c.active) send_encrypted(&c,VN_GOODBYE,NULL,0);
    status(&c); result=0;
out:
    if (ep>=0&&close(ep)<0) result=1;

    if (timer>=0&&close(timer)<0) result=1;

    if (signals>=0&&close(signals)<0) result=1;

    if (c.udp>=0&&close(c.udp)<0) result=1;

    if (c.tap>=0&&close(c.tap)<0) result=1;
    sodium_memzero(&c,sizeof(c)); return result;
}
