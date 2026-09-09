#!/usr/bin/env bash
# Sourced by run-integration.sh; tracks only resources created by this run.
setup_namespaces() {
    for letter in a b c; do
        if ip netns list | awk '{print $1}' | grep -qx "vnet-$letter"; then
            echo "Namespace vnet-$letter already exists; refusing to alter it" >&2; return 1
        fi
        if ip link show "vn-host-$letter" &>/dev/null; then
            echo "Link vn-host-$letter already exists; refusing to alter it" >&2; return 1
        fi
    done
    local i=0 base letter
    for letter in a b c; do
        base=$((i * 4))
        ip netns add "vnet-$letter"
        created_ns+=("vnet-$letter")
        ip link add "vn-host-$letter" type veth peer name "vn-peer-$letter"
        created_links+=("vn-host-$letter")
        ip link set "vn-peer-$letter" netns "vnet-$letter"
        ip address add "172.30.77.$((base+1))/30" dev "vn-host-$letter"
        ip link set "vn-host-$letter" up
        ip -n "vnet-$letter" link set lo up
        ip -n "vnet-$letter" address add "172.30.77.$((base+2))/30" dev "vn-peer-$letter"
        ip -n "vnet-$letter" link set "vn-peer-$letter" up
        # IPv6 is out of scope; disable it only inside these test namespaces.
        ip netns exec "vnet-$letter" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
        i=$((i+1))
    done
}
cleanup_namespaces() {
    local name
    for name in "${created_ns[@]}"; do ip netns delete "$name" || true; done
    for name in "${created_links[@]}"; do ip link delete "$name" 2>/dev/null || true; done
}
