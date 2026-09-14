# vnet

`vnet` connects Linux machines to the same small virtual Ethernet network.
Programs on those machines send normal Ethernet frames through a TAP
interface; `vnet` encrypts the frames, carries them over UDP, and delivers them
through a central switch.

If TAP interfaces are new to you, think of `vnet0` as a software network card.
The operating system writes an Ethernet frame to it, and `vnet-client` moves
that frame to the other machines.

## What you need

- Two or more Linux machines, or Linux network namespaces for testing
- Root access on each client so it can create a TAP interface
- UDP port 9993 reachable on the machine running `vnet-switch`

Install the dependencies and build the programs:

```sh
sudo apt install build-essential pkg-config libsodium-dev libmnl-dev \
  iproute2 util-linux
make
make test
```

The build creates `vnet-switch`, `vnet-client`, and `vnet-keygen` under `bin/`.

## 1. Create the switch identity

On the machine that will run the switch:

```sh
mkdir -p config
./bin/vnet-keygen config/switch.key > config/switch.pub
```

`switch.key` is private and must stay on the switch. Copy `switch.pub` to every
client through a trusted channel; clients use it to make sure they reached the
correct switch.

## 2. Create a client identity

On the first client:

```sh
mkdir -p config
./bin/vnet-keygen config/alice.key \
  > config/alice.pub 2> config/alice.identity
cat config/alice.identity
```

The last line starts with `allowlist:`. Add its two hexadecimal values to the
switch's allowlist:

```sh
awk '/^allowlist:/ {print $2, $3}' config/alice.identity \
  > config/allowed-peers.conf
```

For another client, generate a different key and append its allowlist line
with `>>` instead of replacing the file. Never share a client's `.key` file.

## 3. Start the switch

```sh
./bin/vnet-switch --bind 0.0.0.0:9993 --network-id labnet \
  --identity config/switch.key --allowlist config/allowed-peers.conf
```

`labnet` is the virtual network name. Every client must use the same name.

## 4. Join from a client

Choose an unused address for this client inside the virtual network. Replace
the documentation address below with the switch machine's real IPv4 address:

```sh
RELAY_IP=192.0.2.10

sudo ./bin/vnet-client --server "$RELAY_IP:9993" --network-id labnet \
  --identity config/alice.key --relay-public-key config/switch.pub \
  --interface vnet0 --address 10.77.0.2/24
```

Give the next client a different address, such as `10.77.0.3/24`. Once both
clients are connected, test the overlay from the first one:

```sh
ping 10.77.0.3
```

The `10.77.0.x` addresses belong to the virtual network. The switch's normal
IPv4 address is only used to carry the encrypted UDP packets underneath it.

## How frames move

The switch learns which client sent each source MAC address. Known unicast
frames go only to the matching client. Broadcasts, multicast frames, and
unknown destinations are copied to the other active clients. Entries age out,
dead peers expire, and clients repeat the handshake after a timeout or switch
restart.

Persistent X25519 keys authenticate peers. Established sessions use
XChaCha20-Poly1305, and packet numbers reject duplicates and old packets. The
central switch can still see decrypted Ethernet frames, so this protects the
transport to a trusted switch; it is not end-to-end encryption between
clients.

The project does not provide DHCP, routing, or Internet access. It only creates
the TAP interface and carries its Ethernet frames.

## More tests

```sh
make sanitize
sudo make integration
```

`make sanitize` runs the unit tests with ASan and UBSan. The integration test
creates real network namespaces and TAP devices, so run it on a disposable
Linux test machine.
