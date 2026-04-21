#include "vnet_switch.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
static int number(const char *s, unsigned *out, unsigned min, unsigned max) {
    char *end; errno=0; unsigned long n=strtoul(s,&end,10);

    if (errno||!*s||*end||n<min||n>max) return -1;
    *out=(unsigned)n; return 0;
}
int vn_options_parse(int argc, char **argv, struct vn_options *o, int server) {
    *o=(struct vn_options){.mtu=VN_MTU,.peer_timeout=30,.mac_age=60};

    static const struct option opts[]={
        {"bind",required_argument,NULL,'b'}, {"server",required_argument,NULL,'s'},
        {"network-id",required_argument,NULL,'n'}, {"identity",required_argument,NULL,'i'},
        {"allowlist",required_argument,NULL,'a'}, {"relay-public-key",required_argument,NULL,'r'},
        {"interface",required_argument,NULL,'t'}, {"address",required_argument,NULL,'d'},
        {"mtu",required_argument,NULL,'m'}, {"peer-timeout",required_argument,NULL,'p'},
        {"mac-age",required_argument,NULL,'g'}, {"help",no_argument,NULL,'h'}, {NULL,0,NULL,0}};
    int c;

    while ((c=getopt_long(argc,argv,"",opts,NULL))!=-1) {
        switch (c) {
        case 'b': if (!server) return -1; o->endpoint=optarg; break;
        case 's': if (server) return -1; o->endpoint=optarg; break;
        case 'n': o->network=optarg; break;
        case 'i': o->identity=optarg; break;
        case 'a': o->allowlist=optarg; break;
        case 'r': o->relay_key=optarg; break;
        case 't': o->interface=optarg; break;
        case 'd': o->address=optarg; break;
        case 'm': if (number(optarg,&o->mtu,576,VN_MAX_MTU)) return -1; break;
        case 'p': if (number(optarg,&o->peer_timeout,3,86400)) return -1; break;
        case 'g': if (number(optarg,&o->mac_age,1,86400)) return -1; break;
        default: return -1;
        }
    }

    if (optind!=argc||!o->endpoint||!o->network||!vn_network_valid(o->network)||!o->identity) return -1;

    return server?(!o->allowlist?-1:0):(!o->relay_key||!o->interface||!o->address?-1:0);
}
int vn_allowlist(const char *path, struct vn_peer peers[VN_PEERS], size_t *count) {
    FILE *f=fopen(path,"r"); char line[256]; int result=-1; *count=0;

    if (!f) return -1;

    while (fgets(line,sizeof(line),f)) {
        char node[33],pk[65],extra; uint8_t expected[16];

        char *start=line; while (*start==' '||*start=='\t') start++;

        if (*start=='#'||*start=='\n'||!*start) continue;

        if (!strchr(line,'\n')&&!feof(f)) goto out;

        if (*count==VN_PEERS||sscanf(start,"%32s %64s %c",node,pk,&extra)!=2) goto out;

        struct vn_peer *peer=&peers[*count];

        if (vn_unhex(peer->node,16,node)||vn_unhex(peer->pk,32,pk)) goto out;
        vn_node(expected,peer->pk);

        if (memcmp(expected,peer->node,16)||vn_peer_find(peers,*count,peer->node)>=0) goto out;
        ++*count;
    }

    if (!ferror(f)&&*count) result=0;
out:
    if (fclose(f)) result=-1;

    return result;
}
