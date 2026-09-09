#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $EUID == 0 ]] || { echo "Run with sudo" >&2; exit 1; }
BIN=$(realpath "${VNET_BIN:-bin}")
mkdir -p tests/artifacts
ART=$(mktemp -d "$PWD/tests/artifacts/run-XXXXXXXX")
chmod 700 "$ART"
created_ns=() created_links=() clients=() relay_pid= capture_pid= proxy_pid=
source tests/setup-namespaces.sh
cleanup() {
    local pid
    [[ -z $capture_pid ]] || kill -INT "$capture_pid" 2>/dev/null || true
    for pid in "${clients[@]}"; do kill -CONT "$pid" 2>/dev/null || true; kill -TERM "$pid" 2>/dev/null || true; done
    for pid in "${clients[@]}"; do wait "$pid" 2>/dev/null || true; done
    [[ -z $relay_pid ]] || kill -TERM "$relay_pid" 2>/dev/null || true
    [[ -z $relay_pid ]] || wait "$relay_pid" 2>/dev/null || true
    [[ -z $capture_pid ]] || wait "$capture_pid" 2>/dev/null || true
    [[ -z $proxy_pid ]] || kill -TERM "$proxy_pid" 2>/dev/null || true
    [[ -z $proxy_pid ]] || wait "$proxy_pid" 2>/dev/null || true
    cleanup_namespaces
    # Ephemeral test private keys need not survive; retain inspectable logs/public files.
    rm -f "$ART"/*.key
    echo "Artifacts: $ART"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
wait_log() {
    local pattern=$1 file=$2
    for ((try=0;try<100;try++)); do
        if grep -q "$pattern" "$file"; then return 0; fi
        sleep .1
    done
    echo "Timed out waiting for $pattern in $file" >&2; cat "$file" >&2; return 1
}
wait_count() {
    local pattern=$1 file=$2 expected=$3 count
    for ((try=0;try<100;try++)); do
        count=$(grep -c "$pattern" "$file" || true)
        if ((count >= expected)); then return 0; fi
        sleep .1
    done
    echo "Timed out waiting for $expected occurrences of $pattern in $file" >&2
    cat "$file" >&2; return 1
}
for name in relay a b c outsider; do
    "$BIN/vnet-keygen" "$ART/$name.key" >"$ART/$name.pub" 2>"$ART/$name.identity"
done
awk '/^allowlist:/ {print $2, $3}' "$ART/"{a,b,c}.identity >"$ART/allowed.conf"
setup_namespaces
start_relay() {
    local age=$1 log=$2
    "$BIN/vnet-switch" --bind 0.0.0.0:9993 --network-id labnet --identity "$ART/relay.key" \
        --allowlist "$ART/allowed.conf" --peer-timeout 6 --mac-age "$age" >"$log" 2>&1 &
    relay_pid=$!
    wait_log relay_ready "$log"
}
"$BIN/test_proxy" "$ART/control.sock" >"$ART/proxy.log" 2>&1 &
proxy_pid=$!
wait_log proxy_ready "$ART/proxy.log"
start_relay 60 "$ART/relay-ns.log"
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
# Negative real-client sessions, inside A, with their own temporary TAP.
for test in wrong-network unauthorized; do
    identity=a network=labnet
    if [[ $test == wrong-network ]]; then network=wrongnet; else identity=outsider; fi
    ip netns exec vnet-a "$BIN/vnet-client" --server 172.30.77.1:9993 --network-id "$network" \
        --identity "$ART/$identity.key" --relay-public-key "$ART/relay.pub" --interface vnet-denied \
        --address 10.77.0.98/24 --peer-timeout 3 >"$ART/$test.log" 2>&1 &
    clients+=("$!")
    wait_log connecting "$ART/$test.log"; sleep 2
    kill -TERM "${clients[0]}"; wait "${clients[0]}"; clients=()
    if grep -q session_active "$ART/$test.log" || grep -q peer_active "$ART/relay-ns.log"; then
        echo "FAIL $test authenticated" >&2; exit 1
    fi
    echo "PASS namespace real client rejected: $test"
done
start_client() {
    local i=$1 mtu=$2 letter endpoint
    local letters=(a b c)
    letter=${letters[i]}
    endpoint="172.30.77.$((i*4+1)):9993"
    [[ $i != 0 ]] || endpoint=172.30.77.1:10000
    ip netns exec "vnet-$letter" "$BIN/vnet-client" --server "$endpoint" \
        --network-id labnet --identity "$ART/$letter.key" --relay-public-key "$ART/relay.pub" \
        --interface vnet0 --address "10.77.0.$((i+2))/24" --mtu "$mtu" --peer-timeout 6 \
        >>"$ART/client-$letter.log" 2>&1 &
    clients[i]=$!
}
for i in 0 1 2; do start_client "$i" 1300; done
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
ip netns exec vnet-a tcpdump -l -n -e -i vnet0 'arp or icmp' >"$ART/ethernet.txt" 2>"$ART/tcpdump.log" &
capture_pid=$!
wait_log 'listening on' "$ART/tcpdump.log"
for spec in 'a 3' 'a 4' 'b 2' 'b 4' 'c 2' 'c 3'; do
    read -r letter dest <<<"$spec"
    ip netns exec "vnet-$letter" ping -n -c 2 -W 2 "10.77.0.$dest" >>"$ART/ping.txt"
done
ip netns exec vnet-a ping -n -c 2 -W 2 -M do -s 1272 10.77.0.3 >>"$ART/ping.txt"
ip -n vnet-a neighbour show dev vnet0 | tee "$ART/neighbours.txt"
grep -q '10.77.0.3.*lladdr' "$ART/neighbours.txt"
grep -q '10.77.0.4.*lladdr' "$ART/neighbours.txt"
kill -INT "$capture_pid"; wait "$capture_pid"; capture_pid=
grep -q 'ARP .*Request' "$ART/ethernet.txt"
grep -q 'ARP .*Reply' "$ART/ethernet.txt"
echo 'PASS TAP ARP request/reply; all six directed client pings; 1300-byte IP packet'
# Long MAC age proves expiration removes still-fresh mappings.
kill -STOP "${clients[2]}"
wait_log 'peer_expire peer=2 reason=timeout' "$ART/relay-ns.log"
grep -q 'mac_remove peer=2' "$ART/relay-ns.log"
echo 'PASS stopped namespace client expires and its MAC is removed before MAC-age limit'
kill -CONT "${clients[2]}"
sleep 7
ip netns exec vnet-c ping -n -c 2 -W 2 10.77.0.2 >>"$ART/ping.txt"
[[ $(grep -c session_active "$ART/client-c.log") -ge 2 ]]
echo 'PASS client reconnects after session expiration'
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
echo 'PASS clients recover after relay restart'
"$BIN/test_namespace" "$ART/control.sock" age | tee "$ART/namespace-age.txt"
grep -q 'mac_age peer=' "$ART/relay-restart.log"
for pid in "${clients[@]}"; do kill -TERM "$pid"; done
for pid in "${clients[@]}"; do wait "$pid"; done
clients=()
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
if grep -ER 'AddressSanitizer|runtime error:|LeakSanitizer' "$ART"/*.log; then exit 1; fi
kill -TERM "$proxy_pid"; wait "$proxy_pid"; proxy_pid=
echo 'PASS all namespace/TAP, fault-proxy, and supplemental live-relay integration checks'
