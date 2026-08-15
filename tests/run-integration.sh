"$BIN/test_proxy" "$ART/control.sock" >"$ART/proxy.log" 2>&1 &
proxy_pid=$!
wait_log proxy_ready "$ART/proxy.log"
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
for letter in a b c; do wait_log session_active "$ART/client-$letter.log"; done
"$BIN/test_namespace" "$ART/control.sock" forward | tee "$ART/namespace-forward.txt"
kill -USR1 "$relay_pid"; sleep .2
grep -Eq 'replay=[1-9]' "$ART/relay-ns.log"
grep -Eq 'bad_tag=[1-9]' "$ART/relay-ns.log"
"$BIN/test_namespace" "$ART/control.sock" relay-error | tee "$ART/namespace-relay-error.txt"
wait_log 'error_sent peer=0 reason=invalid-ethernet' "$ART/relay-ns.log"
wait_log error_received "$ART/client-a.log"
wait_count session_active "$ART/client-a.log" 2
echo 'PASS relay emits authenticated ERROR; real client handles it and reconnects'
# Intentional MTU mismatch to trigger the client's authenticated ERROR path.
kill -TERM "${clients[2]}"; wait "${clients[2]}"
previous=$(grep -c session_active "$ART/client-c.log")
start_client 2 1200
wait_count session_active "$ART/client-c.log" "$((previous+1))"
"$BIN/test_namespace" "$ART/control.sock" client-error | tee "$ART/namespace-client-error.txt"
wait_log 'error_sent reason=invalid-frame-size' "$ART/client-c.log"
wait_log 'peer_expire peer=2 reason=remote-error' "$ART/relay-ns.log"
wait_count session_active "$ART/client-c.log" "$((previous+2))"
echo 'PASS real client emits authenticated ERROR; relay handles it; client reconnects'

kill -TERM "$relay_pid"; wait "$relay_pid"; relay_pid=
start_relay 2 "$ART/relay-restart.log"
# C's deliberate stop/recreation assigned a new TAP MAC; remove old kernel ARP.
for letter in a b c; do ip -n "vnet-$letter" neighbour flush dev vnet0; done
sleep 3
ip netns exec vnet-a ping -n -c 2 -W 2 10.77.0.4 >>"$ART/ping.txt"
kill -TERM "$relay_pid"; wait "$relay_pid"; relay_pid=
start_relay 2 "$ART/relay-probes.log"
"$BIN/test_overlay" 127.0.0.1:9993 "$ART/relay.pub" "$ART/a.key" "$ART/b.key" "$ART/c.key" "$ART/outsider.key" | tee "$ART/probes.txt"
kill -USR1 "$relay_pid"
sleep .2
kill -TERM "$relay_pid"; wait "$relay_pid"; relay_pid=
grep -Eq 'replay=[1-9]' "$ART/relay-probes.log"
grep -Eq 'bad_tag=[1-9]' "$ART/relay-probes.log"
grep -q 'mac_age peer=' "$ART/relay-probes.log"
grep -q 'mac_move peer=2 previous=1' "$ART/relay-probes.log"
