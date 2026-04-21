#include "vnet_crypto.h"
#include "vnet_util.h"
#include <sodium.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void vn_node(uint8_t node[16], const uint8_t pk[32]) {
    if (crypto_generichash(node,16,pk,32,NULL,0)) abort(); /* fixed valid parameters */
}
static int read_exact(int fd, uint8_t *p, size_t n) {
    while (n) {
        ssize_t r=read(fd,p,n);

        if (r<0&&errno==EINTR) continue;

        if (r<=0) return -1;
        p+=(size_t)r; n-=(size_t)r;
    }

    return 0;
}
int vn_identity_load(const char *path, struct vn_identity *id, int create) {
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);

    if (fd<0&&errno==ENOENT&&create) {
        if (crypto_kx_keypair(id->pk,id->sk)) return -1;
        fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);

        if (fd<0) { sodium_memzero(id,sizeof(*id)); return -1; }
        uint8_t raw[64]; memcpy(raw,id->pk,32); memcpy(raw+32,id->sk,32);

        size_t off=0; int ok=0;

        while (off<sizeof(raw)) {
            ssize_t w=write(fd,raw+off,sizeof(raw)-off);

            if (w<0&&errno==EINTR) continue;

            if (w<=0) { ok=-1; break; }
            off+=(size_t)w;
        }

        if (fsync(fd)<0) ok=-1;

        if (close(fd)<0) ok=-1;
        sodium_memzero(raw,sizeof(raw));

        if (ok) { vn_cleanup_unlink(path); sodium_memzero(id,sizeof(*id)); return -1; }
    } else {
        if (fd<0) return -1;

        struct stat st; uint8_t raw[64], pk[32];

        int ok=fstat(fd,&st);

        if (!ok&&(!S_ISREG(st.st_mode)||(st.st_mode&077)||st.st_size!=64)) ok=-1;

        if (!ok) ok=read_exact(fd,raw,sizeof(raw));

        if (close(fd)<0) ok=-1;

        if (ok) { sodium_memzero(raw,sizeof(raw)); return -1; }
        memcpy(id->pk,raw,32); memcpy(id->sk,raw+32,32);
        sodium_memzero(raw,sizeof(raw));

        if (crypto_scalarmult_base(pk,id->sk)||sodium_memcmp(pk,id->pk,32)) {
            sodium_memzero(id,sizeof(*id)); return -1;
        }
    }
    vn_node(id->node,id->pk); return 0;
}
int vn_public_load(const char *path, uint8_t pk[32]) {
    FILE *f=fopen(path,"r"); char hex[67];
