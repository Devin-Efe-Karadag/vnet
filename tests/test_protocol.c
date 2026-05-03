    assert(!memcmp(plain,frame,60));
    int old_n=vn_seal(&client,"labnet",a.node,VN_KEEPALIVE,NULL,0,saved);
    assert(vn_open(&server,"labnet",packet,(size_t)n,&h,plain)==0);
    old_n=vn_seal(&client,"labnet",a.node,VN_KEEPALIVE,NULL,0,saved);
    n=vn_seal(&client,"labnet",a.node,VN_KEEPALIVE,NULL,0,packet);
    assert(vn_open(&server,"labnet",saved,(size_t)old_n,&h,plain)==-2);
    struct vn_session other;
    assert(vn_derive(&other,&a,b.pk,challenge,sid,"labnet",0)==0);
    client.sent=UINT64_MAX;
    uint8_t zero[32]={0}; assert(vn_derive(&other,&a,zero,challenge,sid,"labnet",0)==-1);
    vn_mac_learn(table,mac,0,100); assert(vn_mac_find(table,mac)==0);
    vn_mac_age(table,102,2); assert(vn_mac_find(table,mac)==1);
    vn_mac_learn(table,mac,2,104); vn_mac_remove_peer(table,2); assert(vn_mac_find(table,mac)==-1);
    for (unsigned i=0;i<VN_MACS;i++) { table[i].used=1; table[i].seen=100+i; table[i].addr[0]=4; }
    sodium_memzero(&a,sizeof(a)); sodium_memzero(&b,sizeof(b));
    assert(puts("PASS protocol: wire offsets, directional keys/nonces, bidirectional ERROR, AEAD, tamper, replay/reorder/stale, session binding, wrap, MAC move/aging/replacement")>=0);
}
