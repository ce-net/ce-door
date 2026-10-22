# ce-wire: typed calls between ce-net apps (design, not built yet)

Goal: type safety end to end across applications communicating over ce-net, in low-level Rust. So ce-wire is
ce-net's app-to-app transport, not a per-app helper.

## Layers

1. `ce-wire` core, `#![no_std]`, no alloc, zero deps except serde + postcard: frame header, op trait, encode/decode
   into caller buffers. MCU firmware and the daemon share this.
2. `ce-wire` feature `std` (+ tokio): `Client`, `Server`, connection pool, deadlines, Hello handshake.
3. `<app>-api` crates (e.g. `servo-bus-api`): the app's ops and types, nothing else. Client and server both depend
   on it, so a type change that breaks a caller fails to compile, never at runtime.

## Frame (little-endian)

`u32 len | u8 kind | u64 req_id | u32 op | payload(postcard)`; header 17 bytes. kind: 0 Hello, 1 Req, 2 Resp,
3 Err, 4 Datagram (UDP, <= 1200 B payload on nm0, carries a u32 seq; stale seqs dropped, never queued).

## Typed ops

```rust
ce_wire::api! {
    api servo_bus = "servo.bus", version 1;
    1 => Goal(GoalReq) -> GoalAck;
    2 => Hold(HoldReq) -> HoldAck;
    3 => State(()) -> BusState;
}
// generates: struct Goal; impl ce_wire::Op for Goal { const ID: u32 = 1; type Req = GoalReq; type Resp = GoalAck; }
// and const SCHEMA: u64 = fnv64 over "servo.bus/1" + every op line + the token text of each type definition.

let ack: GoalAck = client.call::<Goal>(&GoalReq { .. }).await?;      // only GoalReq compiles here
server.on::<Goal>(|req: GoalReq, who: &Caller| async move { .. -> GoalAck });
```

## Handshake and rights

First frame Hello = { api name, version, SCHEMA hash, ce-cap token }. Server refuses a hash mismatch (typed error naming
both hashes) and a token that ce-iam does not verify. Per-op required right is declared in the api! line
(`1 => Goal(GoalReq) -> GoalAck, needs "servo.goal";`), so priority/permission is part of the type, which is what
a servo controller needs (priority as a right, not a claim).

## Errors and time

`WireError::{Timeout, Refused{right}, Schema{ours, theirs}, Remote(String), Io}`. Default deadline 1 s, instant
reconnect (net.mesh failover stall 0.84-1.9 s). TCP_NODELAY, keepalive 10 s.

## Built 2026-10-11 (skeleton)

`src/lib.rs` (no_std core: Header, Kind, Api, Op, fnv64, `api!`), `src/net.rs` (tokio Client<A>/Server<A>, Hello,
Refusal, Caller, 1 s deadline). Tests `tests/typed.rs`: typed call, missing right refused, stranger refused, one
field i16 -> i32 refused at connect by schema hash. `--no-default-features` builds (no_std).

Loopback bench, a 4-core Linux box at load 23, one current_thread runtime, 64-byte payload, 20k calls, 2 runs:

| path | p50 | p99 | req/s |
|---|---:|---:|---:|
| ce.peer no-op today (Python -> ce node -> Python) | 14.9 ms | 85.6 ms | 58 |
| ce-wire sequential | 0.0165 ms | 0.053-0.056 ms | 18,834-26,932 |
| ce-wire pipelined, 64 in flight | | | 357,042-377,507 |

+ `DatagramSocket<A>` (UDP, session key + seq, stale and stranger dropped, right per op), `Client::by_name`
(port from name, local then mesh peers, spawn from ceapp.toml `[wire] spawn`). Tests 10/10.

+ typed server-push streams: `streams { N => Live(Req) -> stream Item, needs "r"; }` in `api!`,
`client.subscribe::<Live>(&req)` -> `Subscription` (`next()`, `latest()` = newest queued, older skipped), server
`.stream::<Live,_,_>(|req, who, sink| ..)`, `sink.send(&item)` fails after the client drops it. Frame kinds 5 Sub,
6 Item, 7 End (client: cancel; server: normal end). Features: `default-features = false` = types only (no_std, no
tokio) for `<cell>-api` crates; `client`; `server`. Tests 11/11.

Not built yet: ce-gate (ce-iam verify of the token), pyo3 binding, reconnect, `describe` op.

## Door and blocking side (2026-10-11)

- `ce-door` binary (D12a): one door per machine on `door_port()` = 7700, binds 127.0.0.1 and the nm0 address.
  Cells call `Server::serve_door()`: `REGISTER <api> <schema> <pid>` on the 0600 unix socket `door_sock()`, then
  receive each client's TCP fd by SCM_RIGHTS with the Hello bytes. `Client::by_name(token)`: local door, then every
  mesh peer's door at once, then local door with spawn (`ceapp.toml [wire] spawn`).
  `examples/door_bench.rs` on a 4-core Linux box at load 27: connect + first call p50 0.110 ms direct, 0.130 ms through
  the door (+20 us once per connection); calls after connect p50 15.6 us direct, 15.8 us handed over (no cost).
- Feature `blocking` (`ce_wire::blocking::{Server, Client, Sink, DatagramSocket}`): std threads, deps serde +
  postcard only (`cargo tree`: ce-wire, postcard, cobs, serde, thiserror). Same frames, Hello, schema check, gate,
  rights, session keys, datagram stale-drop, Sub/Item/End streams. Server: one thread per connection, requests in
  order on it, one thread per open stream. Client: one call at a time, `DEADLINE` read timeout.
  `tests/blocking.rs` checks blocking<->blocking, tokio client -> blocking server (calls + stream), blocking client
  -> tokio server, datagrams. Shared types moved to `proto.rs`.
- Cargo for a thread daemon: `ce-wire = { path = "../ce-wire", default-features = false, features = ["blocking"] }`.

## ce-gate (D11a, 2026-10-11): crates/ce-gate

Hello.token = `ce_gate::proof::<A>(&identity, &chain)`: postcard `Proof {requester node id, unix_ms, 16 B nonce,
chain bytes, ed25519 sig}` over `"ce-wire-hello-v1"|api|schema|unix_ms|nonce|requester|chain`. Cell:
`Server::new(ce_gate::Gate::<A>::new(self_id, roots).into_fn())` (tokio or blocking). Checks: signature, skew
<= 30 s, nonce unseen for 60 s (max 200k kept), `ce_cap::authorize` (root = this node or an accepted root, every link
signed/unexpired/not in `~/.local/share/ce/revocations.json`/applies here/attenuates, leaf held by requester), then
the caller gets each right in `A::RIGHTS` (new const from `api!`) that a leaf ability covers (`x`, `*`, `domain:*`).
Rights are fixed per connection. Cost on a 4-core Linux box at load 22: check 92.5 us per connection, proof 25.7 us.
Name rights `domain:verb` (e.g. `servo.bus:goal`) so ce-cap's `servo.bus:*` wildcard works; `servo.goal` style only
matches exactly or `*`. Get a chain: `ce-iam grant --to <client node id hex> --action servo.bus:goal --nonce N`
on the cell's node, then `ce_gate::chain_from_hex(token)` on the client.

## Name -> machines (D12a,)

ce-door advertises `wire:<api>` in the ce node DHT (`POST :8844/discovery/advertise`) when a cell's first process
registers, and again every 5 min. With `NETMESH_CONTROL` set it rewrites `~/.config/ce-wire/peers` as
`<mesh addr> <node id>` from `netmesh peers` every 60 s (net.mesh node id = ce node id, same
key). `by_name` asks `GET /discovery/find/wire:<api>` (0.5-1.2 ms local) and
dials only the peers whose node id advertises the API; all peers when the DHT has no answer. Known gap: the node has
no un-advertise, so a stopped cell stays listed; the door then answers NoCell and the client moves on.

## A repo is a cell; needs, place, stop, move (2026-10-11)

One repo is one cell: a repo is how a cell reproduces itself. Cells declare dependencies, spawn the cells they need
automatically, and move across the network.

- **Manifest**: `cell.toml` with `[cell]` (old `ceapp.toml` `[wire]` still read): `api`, `spawn = [argv]`,
  `build = [argv]`, `needs = [api, ...]`.
- **Reproduce**: a door asked for a cell it has no manifest for looks it up in `cells.index` (`<api> <git url> <dir>`,
  `$CE_CELLS_INDEX` or `~/dev/rust-stack/cells.index`), clones `--depth 1` into the apps root, runs `build`, spawns.
  The first caller gets `NoCell("... reproducing ..., retry")`; build time is the repo's.
- **Needs**: `ensure(api)` starts needs depth first, each once, skipping what is registered, then the cell
  (test: a needs b,c; c needs b -> "started t.b; started t.c; started t.a").
- **Spawn gate**: the `ce-door` binary (now in `crates/ce-gate`, feature `door`) starts a cell for a remote Hello only
  if its ce-gate proof is signed, within 30 s, and its ce-cap chain (rooted at this node or a mesh peer) grants
  `<api>:spawn`. Before this, anyone reaching :7700 could make a door start any manifest it found.
- **Control** (Unix socket, this user): `PLACE <api>`, `STOP <api>` (shuts the registration; `serve_door` returns,
  the process ends), `LIST`. CLI: `ce-door list | place <api> [mesh ip] | stop <api> | move <api> <mesh ip>`.
  `move` = remote place (spawning Hello with a self-signed `<api>:spawn` cap), then local stop; `by_name` then finds
  the cell on the other machine through the DHT advert.
- Open: state that moves with a cell (state.store makes a cell stateless, so moving is restart elsewhere); placement
  policy (which machine) is the caller's choice today.
