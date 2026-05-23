    return -1;
}
void vn_mac_learn(struct vn_mac *t, const uint8_t *mac, unsigned peer, uint64_t now) {
    unsigned slot=0; int free_slot=-1;

    for (unsigned i=0;i<VN_MACS;i++) {
        if (t[i].used&&!memcmp(t[i].addr,mac,6)) {
            if (t[i].peer!=peer) vn_log("mac_move peer=%u previous=%u",peer,t[i].peer);
            t[i].peer=peer; t[i].seen=now; return;
        if (!t[i].used&&free_slot<0) free_slot=(int)i;

        if (t[i].seen<t[slot].seen) slot=i;
    }

    if (free_slot>=0) slot=(unsigned)free_slot;
    t[slot]=(struct vn_mac){.used=1,.peer=peer,.seen=now}; memcpy(t[slot].addr,mac,6);
    vn_log("mac_learn peer=%u",peer);
