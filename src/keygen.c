#include "vnet_util.h"
#include <sodium.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc!=2) { if (fprintf(stderr,"usage: %s IDENTITY.key > IDENTITY.pub\n",argv[0])<0) return 1; return 2; }

    if (sodium_init()<0) return 1;

    struct vn_identity id;

    if (vn_identity_load(argv[1],&id,1)) { perror("identity (requires regular 0600 file)"); return 1; }

    char pk[65],node[33]; vn_hex(pk,id.pk,32); vn_hex(node,id.node,16);

    int r=printf("%s\n",pk)<0?1:0;

    if (fprintf(stderr,"node-id %s\nallowlist: %s %s\n",node,node,pk)<0||fflush(stderr)) r=1;

    if (fflush(stdout)) r=1;
    sodium_memzero(&id,sizeof(id)); return r;
}
