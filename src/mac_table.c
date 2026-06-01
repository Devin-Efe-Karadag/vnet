#include <string.h>
    for (unsigned i=0;i<VN_MACS;i++) if (t[i].used&&t[i].peer==peer) {
        t[i].used=0; vn_log("mac_remove peer=%u",peer);
}
void vn_mac_age(struct vn_mac *t, uint64_t now, unsigned age) {
    for (unsigned i=0;i<VN_MACS;i++) if (t[i].used&&now-t[i].seen>=age) {
        t[i].used=0; vn_log("mac_age peer=%u",t[i].peer);
    }
}
int vn_mac_find(const struct vn_mac *t, const uint8_t *mac) {
    for (unsigned i=0;i<VN_MACS;i++) if (t[i].used&&!memcmp(t[i].addr,mac,6)) return (int)t[i].peer;

    return -1;
}
void vn_mac_learn(struct vn_mac *t, const uint8_t *mac, unsigned peer, uint64_t now) {
    unsigned slot=0; int free_slot=-1;

    for (unsigned i=0;i<VN_MACS;i++) {
        if (t[i].used&&!memcmp(t[i].addr,mac,6)) {
            if (t[i].peer!=peer) vn_log("mac_move peer=%u previous=%u",peer,t[i].peer);
            t[i].peer=peer; t[i].seen=now; return;
        }

        if (!t[i].used&&free_slot<0) free_slot=(int)i;

        if (t[i].seen<t[slot].seen) slot=i;
    }

    if (free_slot>=0) slot=(unsigned)free_slot;
    t[slot]=(struct vn_mac){.used=1,.peer=peer,.seen=now}; memcpy(t[slot].addr,mac,6);
    vn_log("mac_learn peer=%u",peer);
}
