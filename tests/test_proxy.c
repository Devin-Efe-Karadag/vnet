/* Test-only fault injection: no keys, no decryption, no production hook.
 * A's real client connects to :10000; this proxy forwards to the real relay.
 * A local UNIX seqpacket controller arms one mutation in either direction. */
#include "vnet_util.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/un.h>
int main(int argc, char **argv) {
    assert(argc==2&&strlen(argv[1])<sizeof(((struct sockaddr_un *)0)->sun_path));

    struct sockaddr_in listen_addr,relay,client={0};
    assert(vn_endpoint("0.0.0.0:10000",&listen_addr)==0);
    assert(vn_endpoint("127.0.0.1:9993",&relay)==0);

    int front=vn_udp(&listen_addr),back=vn_udp(NULL),timer,signals;

    int ep=vn_events(&timer,&signals);

    int listener=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    assert(front>=0&&back>=0&&ep>=0&&listener>=0);

    struct sockaddr_un local={.sun_family=AF_UNIX}; strcpy(local.sun_path,argv[1]);
    assert(bind(listener,(struct sockaddr *)&local,sizeof(local))==0&&listen(listener,1)==0);
    assert(vn_epoll_add(ep,front)==0&&vn_epoll_add(ep,back)==0&&vn_epoll_add(ep,listener)==0);

    int controller=-1,running=1; char mode=0,direction=0;
    vn_log("proxy_ready");

    while (running) {
        struct epoll_event events[8]; int count=epoll_wait(ep,events,8,-1);

        if (count<0&&errno==EINTR) continue;
        assert(count>=0);

        for (int i=0;i<count;i++) {
            int fd=events[i].data.fd;

            if (fd==listener) {
                int next=accept4(fd,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC);

                if (next<0&&errno==EAGAIN) continue;
                assert(next>=0&&controller<0); controller=next;
                assert(vn_epoll_add(ep,controller)==0);
            } else if (fd==controller) {
                char command[2]; ssize_t n=recv(fd,command,sizeof(command),0);

                if (n<0&&errno==EAGAIN) continue;

                if (!n) { assert(close(controller)==0); controller=-1; continue; }
                assert(n==2&&strchr("RTNVLOUSX",command[0])&&strchr("ud",command[1]));
                mode=command[0]; direction=command[1];
                assert(send(fd,command,sizeof(command),MSG_NOSIGNAL)==sizeof(command));
            } else if (fd==timer) {
                uint64_t ticks; assert(read(fd,&ticks,sizeof(ticks))==sizeof(ticks));
            } else if (fd==signals) {
                struct signalfd_siginfo sig; assert(read(fd,&sig,sizeof(sig))==sizeof(sig));

                if (sig.ssi_signo!=SIGUSR1) running=0;
            } else {
                uint8_t packet[2000]; struct sockaddr_in from; socklen_t size=sizeof(from);

                ssize_t n=recvfrom(fd,packet,sizeof(packet),0,(struct sockaddr *)&from,&size);

                if (n<0&&errno==EAGAIN) continue;
                assert(n>=0&&size==sizeof(from));

                int uplink=fd==front;

                if (uplink) client=from;
                else if (!vn_same_endpoint(&from,&relay)||!client.sin_port) continue;

                int out=uplink?back:front;

                const struct sockaddr_in *to=uplink?&relay:&client;

                int target=n>=(ssize_t)VN_HEADER&&packet[5]==(mode=='X'?VN_ERROR:VN_DATA);

                if (mode&&direction==(uplink?'u':'d')&&target) {
                    char applied=mode; mode=0;

                    switch (applied) {
                    case 'R': assert(vn_send(out,packet,(size_t)n,to)==0); break;
                    case 'T': case 'X': packet[n-1]^=1; break;
                    case 'N': packet[8]^=1; break;
                    case 'V': packet[4]=255; break;
                    case 'L': n=VN_HEADER-1; break;
                    case 'O': memset(packet+n,0,sizeof(packet)-(size_t)n); n=sizeof(packet); break;
                    case 'U': memset(packet+40,0,16); break;
                    case 'S': packet[56]^=1; break;
                    default: assert(0);
                    }
                    vn_log("fault_applied mode=%c direction=%c",applied,direction);
                }
                assert(vn_send(out,packet,(size_t)n,to)==0);
            }
        }
    }

    if (controller>=0) assert(close(controller)==0);
    assert(close(listener)==0&&close(front)==0&&close(back)==0);
    assert(close(timer)==0&&close(signals)==0&&close(ep)==0);
    assert(unlink(argv[1])==0); return 0;
}
