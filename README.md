# vnet

`vnet` makes a small virtual Ethernet network between Linux machines. Each
machine gets a TAP interface and sends its Ethernet frames over encrypted UDP
to a central switch.

```text
TAP on host A ─┐
TAP on host B ─┼─ encrypted UDP ─ vnet-switch
TAP on host C ─┘
```

The switch learns which client owns each source MAC. Known unicast frames go
to one client; broadcasts, multicast, and unknown destinations are copied to
the other active clients. Entries age out, dead peers expire, and clients try
the handshake again after a timeout or switch restart.

The handshake uses persistent X25519 identities. Clients pin the switch key,
the switch has an allowlist of client keys, and established sessions use
XChaCha20-Poly1305 with separate keys in each direction. Packet numbers and a
sliding window reject duplicates and old packets. The switch still sees the
decrypted frames, so this is transport encryption to a trusted relay rather
than an end-to-end VPN.

## Compiling

```sh
sudo apt install build-essential pkg-config libsodium-dev libmnl-dev \
  iproute2 util-linux
make
make test
```

## Making the keys

```sh
mkdir -p config
./bin/vnet-keygen config/switch.key > config/switch.pub
./bin/vnet-keygen config/alice.key > config/alice.pub 2> config/alice.identity
awk '/^allowlist:/ {print $2, $3}' config/alice.identity \
  > config/allowed-peers.conf
```

The `.key` files are private. Give each client a copy of `switch.pub` through a
trusted channel and add a separate allowlist entry for every client identity.

Start the switch on a machine reachable over UDP/9993:

```sh
./bin/vnet-switch --bind 0.0.0.0:9993 --network-id labnet \
  --identity config/switch.key --allowlist config/allowed-peers.conf
```

Then join from a client with `/dev/net/tun` access:

```sh
sudo ./bin/vnet-client --server relay.example.com:9993 --network-id labnet \
  --identity config/alice.key --relay-public-key config/switch.pub \
  --interface vnet0 --address 10.77.0.2/24
```

Additional clients need their own key and overlay address. The program creates
the TAP interface but does not provide DHCP, routing, or Internet access.

`make sanitize` runs the unit tests with ASan/UBSan. The full namespace and TAP
test is `sudo make integration`.
