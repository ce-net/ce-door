# ce-door

The door of a ce-net machine and the test that proves it is closed to strangers.

- `ce-wire`: typed calls between ce-net services. A client says Hello with the api name, its schema and a capability proof; the server checks the proof before any operation runs.
- `ce-gate`: the gate every service sits behind, and `ce-door`, one door per machine that starts services on demand. Every operation of every service needs its own capability right (see [ce-cap](https://github.com/ce-net/ce-cap)).
- `door-stranger-check`: calls a running door as an anonymous caller, as a stranger with a fresh key, as a stranger asking the door to start a service, and as the owner. PASS only when every stranger is refused and the owner is accepted; a door that refuses everybody is INCONCLUSIVE.

## Build and test

```sh
cargo test
```

## Check a door

```sh
cargo run -p door-stranger-check -- check 127.0.0.1:7700 <api>...    # exit 0 PASS, 1 OPEN, 2 INCONCLUSIVE
```

## License

AGPL-3.0, or a commercial license: see [LICENSING.md](LICENSING.md).
