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
