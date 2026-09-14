# vnet

`vnet` carries Ethernet frames between Linux hosts over encrypted UDP. Each
host gets a TAP interface, so software sees an ordinary network card even
though its frames are crossing a routed network:

```text
host A / vnet0 ─┐
                ├── UDP ── vnet-switch
host B / vnet0 ─┘
```

There are three binaries. `vnet-client` owns a TAP device,
`vnet-switch` relays frames, and `vnet-keygen` creates their identities.
The switch listens on UDP port 9993 by default.

## Compile

```sh
sudo apt install build-essential pkg-config libsodium-dev libmnl-dev \
  iproute2 util-linux
make
make test
```

The binaries are written to `bin/`. Clients require Linux and root access
because creating a TAP interface is privileged.

## Set up a two-host lab

On the relay machine, make the switch key:

```sh
mkdir -p config
./bin/vnet-keygen config/switch.key > config/switch.pub
```

Keep `switch.key` on that machine. Give each client a trusted copy of
`switch.pub`.

Every client also needs its own identity. This example names the first one
Alice:

```sh
mkdir -p config
./bin/vnet-keygen config/alice.key \
  > config/alice.pub 2> config/alice.identity
cat config/alice.identity
```

The printed `allowlist:` line identifies that client. Put its two hex values
in the switch's configuration:

```sh
awk '/^allowlist:/ {print $2, $3}' config/alice.identity \
  > config/allowed-peers.conf
```

Generate a different key for the second host and append its values with `>>`.
Client private keys should never be copied to the relay or to another client.

Now start the relay:

```sh
./bin/vnet-switch --bind 0.0.0.0:9993 --network-id labnet \
  --identity config/switch.key --allowlist config/allowed-peers.conf
```

On Alice's host, replace `192.0.2.10` with the relay machine's real IPv4
address:

```sh
RELAY_IP=192.0.2.10

sudo ./bin/vnet-client --server "$RELAY_IP:9993" --network-id labnet \
  --identity config/alice.key --relay-public-key config/switch.pub \
  --interface vnet0 --address 10.77.0.2/24
```

Start the other client the same way but give it its own key and, for example,
`10.77.0.3/24`. From Alice's machine, `ping 10.77.0.3` should then cross
the overlay.

The `10.77.0.x` addresses exist inside the virtual Ethernet network. They are
separate from the ordinary IP addresses used to reach the relay.

## Packet handling and security

The relay learns the source MAC address belonging to each peer. It sends known
unicast traffic to one peer and floods broadcasts, multicast, and unknown
destinations to the others. Stale MAC entries and silent peers eventually
expire.

Persistent X25519 identities authenticate the handshake. Sessions use
XChaCha20-Poly1305 with separate directional keys, while packet numbers and a
sliding window reject replayed traffic. This protects traffic on its way to a
trusted relay; the relay itself can read the frames. It is not end-to-end
encryption between clients.

There is no DHCP, routing or Internet gateway here. `vnet` only makes the TAP
interface and transports its frames.

For extra checking, `make sanitize` runs the unit tests under ASan/UBSan.
`sudo make integration` creates actual network namespaces and TAP devices,
so use a disposable Linux test machine for that one.
