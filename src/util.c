#include "vnet_util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <sodium.h>
uint64_t vn_now(void) {
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC,&ts)<0) { perror("clock_gettime"); exit(1); }

    return (uint64_t)ts.tv_sec;
}
void vn_log(const char *fmt, ...) {
    va_list ap; va_start(ap,fmt);

    int failed=fprintf(stderr,"[%llu] ",(unsigned long long)vn_now())<0;

    if (vfprintf(stderr,fmt,ap)<0) failed=1;

    if (fputc('\n',stderr)==EOF) failed=1;
    va_end(ap);

    if (failed||fflush(stderr)) _Exit(EXIT_FAILURE);
}
void vn_hex(char *out, const uint8_t *in, size_t n) {
    if (sodium_bin2hex(out,n*2+1,in,n)!=out) abort();
}
void vn_cleanup_close(int fd) {
    int saved=errno;

    if (close(fd)<0) vn_log("cleanup close fd=%d failed: %s",fd,strerror(errno));
    errno=saved;
}
void vn_cleanup_unlink(const char *path) {
    int saved=errno;

    if (unlink(path)<0) vn_log("cleanup unlink failed: %s",strerror(errno));
    errno=saved;
}
int vn_unhex(uint8_t *out, size_t n, const char *in) {
    size_t got=0;

    if (strlen(in)!=n*2) return -1;

    return sodium_hex2bin(out,n,in,n*2,NULL,&got,NULL)||got!=n?-1:0;
}
int vn_endpoint(const char *text, struct sockaddr_in *addr) {
    char copy[64];

    if (strlen(text)>=sizeof(copy)) return -1;
    strcpy(copy,text); char *colon=strrchr(copy,':'), *end;

    if (!colon) return -1;
    *colon++=0; errno=0; unsigned long port=strtoul(colon,&end,10);
    memset(addr,0,sizeof(*addr)); addr->sin_family=AF_INET;

    if (errno||!*colon||*end||!port||port>65535||inet_pton(AF_INET,copy,&addr->sin_addr)!=1) return -1;
    addr->sin_port=htons((uint16_t)port); return 0;
}
int vn_udp(const struct sockaddr_in *addr) {
    int fd=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);

    if (fd<0) return -1;

    if (addr&&bind(fd,(const struct sockaddr *)addr,sizeof(*addr))<0) {
        int e=errno; vn_cleanup_close(fd); errno=e; return -1;
    }

    return fd;
}
int vn_same_endpoint(const struct sockaddr_in *a, const struct sockaddr_in *b) {
    return a->sin_family==b->sin_family&&a->sin_addr.s_addr==b->sin_addr.s_addr&&a->sin_port==b->sin_port;
}
int vn_send(int fd, const void *buf, size_t n, const struct sockaddr_in *to) {
    ssize_t r;
    do { r=sendto(fd,buf,n,0,(const struct sockaddr *)to,sizeof(*to)); } while (r<0&&errno==EINTR);

    return r==(ssize_t)n?0:-1;
}
int vn_epoll_add(int ep, int fd) {
    struct epoll_event ev={.events=EPOLLIN,.data.fd=fd};

    return epoll_ctl(ep,EPOLL_CTL_ADD,fd,&ev);
}
int vn_events(int *timer, int *signals) {
    sigset_t mask;

    if (sigemptyset(&mask)||sigaddset(&mask,SIGINT)||sigaddset(&mask,SIGTERM)||sigaddset(&mask,SIGUSR1)) return -1;

    if (sigprocmask(SIG_BLOCK,&mask,NULL)<0) return -1;

    int ep=epoll_create1(EPOLL_CLOEXEC); *timer=-1; *signals=-1;

    if (ep<0) return -1;
    *timer=timerfd_create(CLOCK_MONOTONIC,TFD_NONBLOCK|TFD_CLOEXEC);
    *signals=signalfd(-1,&mask,SFD_NONBLOCK|SFD_CLOEXEC);

    struct itimerspec tick={.it_interval={.tv_sec=1},.it_value={.tv_sec=1}};

    if (*timer<0||*signals<0||timerfd_settime(*timer,0,&tick,NULL)<0||
        vn_epoll_add(ep,*timer)<0||vn_epoll_add(ep,*signals)<0) {
        int saved=errno;

        if (*timer>=0) vn_cleanup_close(*timer);

        if (*signals>=0) vn_cleanup_close(*signals);
        vn_cleanup_close(ep); *timer=-1; *signals=-1; errno=saved; return -1;
    }

    return ep;
}
