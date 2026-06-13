# A real client must not accept a relay whose identity differs from its pin.
ip netns exec vnet-a "$BIN/vnet-client" --server 172.30.77.1:9993 --network-id labnet \
    --identity "$ART/a.key" --relay-public-key "$ART/outsider.pub" --interface vnet-bad \
    --address 10.77.0.99/24 --peer-timeout 3 >"$ART/wrong-pin.log" 2>&1 &
clients+=("$!")
wait_log connecting "$ART/wrong-pin.log"
sleep 2
kill -TERM "${clients[0]}"; wait "${clients[0]}"; clients=()
if grep -q session_active "$ART/wrong-pin.log" || grep -q peer_active "$ART/relay-ns.log"; then
    echo 'FAIL incorrect relay pin authenticated' >&2; exit 1
fi
echo 'PASS real client rejects incorrect relay identity pin'
kill -TERM "$relay_pid"; wait "$relay_pid"; relay_pid=
start_relay 2 "$ART/relay-restart.log"
# C's deliberate stop/recreation assigned a new TAP MAC; remove old kernel ARP.
for letter in a b c; do ip -n "vnet-$letter" neighbour flush dev vnet0; done
sleep 3
ip netns exec vnet-a ping -n -c 2 -W 2 10.77.0.4 >>"$ART/ping.txt"
