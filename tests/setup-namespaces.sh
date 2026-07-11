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
