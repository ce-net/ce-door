//! Find-or-spawn by name over net.mesh: a caller should never get "site cannot be reached", because every
//! cell lists its dependencies and its start routine, so everything needed starts automatically and connects
//! transparently.
//!
//! The find contract lives here, not in distributed-networking-api, so every client in every language depends on this
//! small stable API (`net.find` v1) and not on the whole control plane's schema hash. net-mesh's control serves
//! `Server::<NetFind>` next to its own API and re-exports these types.
//! Field order is the wire order (postcard is positional): never reorder, add a new op or a new version instead.
//!
//! `Client::<A>::by_name(token)` order:
//! 1. this machine's door, no spawn (no hop when the cell already runs here);
//! 2. `net.find:Find(A::NAME, major)`: every healthy replica whose schema hash equals `A::SCHEMA`, nearest first; the
//!    first that accepts the Hello wins, the next one is tried when one fails (failover);
//! 3. the net.mesh peers' doors at once (the DHT path, for nodes without a finder);
//! 4. this machine's door with spawn (it reads cell.toml `[cell]`/`[launch]`, starts `needs`/`depends_on` first).
//!
//! When all four fail the caller gets [`WireError::Unreachable`]: which cell, the finder's typed answer (which
//! dependency failed and why) and every place tried. That is what an app shows instead of "cannot be reached".
use crate::Api;
#[cfg(any(feature = "client", feature = "blocking"))]
use std::net::SocketAddr;

ce_wire::api! {
    api NetFind = "net.find", version 1;
    types {
        /// One running copy of a named cell.
        pub struct Replica {
            /// `host:port` that answers its Hello (a door or the cell itself); a String so every SDK language and a
            /// `<cell>.ce` name fit
            pub addr: String,
            /// node id (hex) it runs on
            pub node: String,
            /// semver of the cell build
            pub version: String,
            /// `<Api as ce_wire::Api>::SCHEMA` of what it serves
            pub schema_hash: u64,
            /// ms since its health op last answered (0 = just now)
            pub healthy_ms: u32,
        }
        pub struct FindReq { pub name: String, pub major: u16 }
        pub struct FindReply {
            /// healthy replicas of that major, nearest first
            pub replicas: Vec<Replica>,
            /// true when no replica was running and this call started one
            pub spawned: bool,
        }
        pub enum FindError {
            Unauthorized,
            /// no such name and nothing to start under it
            NotFound,
            /// the name is known but no replica runs and it has no start spec
            NoStartSpec,
            /// starting it (or a dependency of it) failed; `dep_chain` runs from the asked name to `cell`
            StartFailed { cell: String, dep_chain: Vec<String>, cause: String },
            Timeout { after_ms: u32 },
        }
    }
    ops {
        1 => Find(FindReq) -> Result<FindReply, FindError>, needs "net.find:find";
    }
}

/// The typed "cannot be reached": an app renders this (cell, failed dependency, cause), never a blank page.
#[derive(Debug, Clone, PartialEq)]
pub struct Unreachable {
    pub api: String,
    pub major: u16,
    /// what net.find said, when it answered with an error
    pub find: Option<FindError>,
    /// every place tried, in order, with why it failed
    pub tried: Vec<String>,
    /// the last error (the local spawn's)
    pub cause: String,
}

impl std::fmt::Display for Unreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.find {
            Some(FindError::StartFailed { cell, dep_chain, cause }) => {
                write!(f, "{}@{} could not start: {cell} failed ({}): {cause}", self.api, self.major, dep_chain.join(" -> "))
            }
            Some(e) => write!(f, "{}@{} not reachable: net.find {e:?}; {}", self.api, self.major, self.cause),
            None => write!(f, "{}@{} not reachable: {}", self.api, self.major, self.cause),
        }
    }
}

#[cfg(any(feature = "client", feature = "blocking"))]
/// The finder's addresses: `$CE_NET_FIND` (comma separated host:port) or this machine's door.
pub fn finders() -> Vec<SocketAddr> {
    match std::env::var("CE_NET_FIND") {
        Ok(v) if !v.trim().is_empty() => v.split(',').filter_map(|s| s.trim().parse().ok()).collect(),
        _ => vec![SocketAddr::from(([127, 0, 0, 1], crate::door_port()))],
    }
}

static MESH_TOKEN: std::sync::OnceLock<fn() -> Vec<u8>> = std::sync::OnceLock::new();

/// How `by_name` proves itself to net.find (a ce-gate proof for `NetFind`); `ce_gate::enable_find()` sets it. Unset:
/// an empty token (an ungated test finder, or a refusal that falls through to the next step).
pub fn set_mesh_token(f: fn() -> Vec<u8>) {
    let _ = MESH_TOKEN.set(f);
}

pub(crate) fn mesh_token() -> Vec<u8> {
    MESH_TOKEN.get().map(|f| f()).unwrap_or_default()
}

#[cfg(any(feature = "client", feature = "blocking"))]
/// How long a find may take: it can start the cell and its dependencies.
pub const FIND_WAIT: std::time::Duration = crate::SPAWN_WAIT;

/// The replicas worth dialing for `A`: same schema hash only (a client never dials a schema it was not built for),
/// healthiest first.
pub fn usable<A: Api>(r: &FindReply) -> Vec<String> {
    usable_with::<A>(r, &[])
}

/// [`usable`], plus replicas at an older schema the caller holds adapters for (`Client::by_name_older`); ours first,
/// then the older ones, each healthiest first.
pub fn usable_with<A: Api>(r: &FindReply, older: &[u64]) -> Vec<String> {
    let mut v: Vec<&Replica> = r.replicas.iter().filter(|x| x.schema_hash == A::SCHEMA || older.contains(&x.schema_hash)).collect();
    v.sort_by_key(|x| (x.schema_hash != A::SCHEMA, x.healthy_ms));
    v.into_iter().map(|x| x.addr.clone()).collect()
}

/// How long `by_name` keeps retrying when net.find knows a replica but none answered (a link blip of
/// 6-8 s must cost latency, not answers). `$CE_WIRE_RETRY_MS` overrides it; 0 turns retrying off.
pub const RETRY_FOR: std::time::Duration = std::time::Duration::from_secs(12);

/// The waits between `by_name` rounds: 250 ms doubling to 2 s, while the next round still starts inside `RETRY_FOR`
/// of `start`. None: give up (then `by_name` asks the local door to spawn).
pub fn retry_wait(start: std::time::Instant, round: u32) -> Option<std::time::Duration> {
    let total = std::env::var("CE_WIRE_RETRY_MS").ok().and_then(|v| v.parse().ok()).map_or(RETRY_FOR, std::time::Duration::from_millis);
    let wait = std::time::Duration::from_millis(250u64 << round.min(3));
    (start.elapsed() + wait < total).then_some(wait)
}

pub(crate) fn major<A: Api>() -> u16 {
    A::VERSION as u16
}

/// Why this machine may not run `api` itself (its cell.toml pins another os, arch or node), or None. A caller that
/// cannot run the cell here must keep dialing the remote replica instead of falling back to a local spawn that is
/// refused anyway (seen: a macOS client sent nothing, "not runnable here, needs os [linux]", because the Linux
/// replica missed the 1 s dial deadline over a 250 ms link).
#[cfg(any(feature = "client", feature = "blocking"))]
pub fn pinned_away(api: &str) -> Option<String> {
    crate::name::find_manifest(api).and_then(|m| crate::name::unmet(&m))
}

/// The dial deadline for a remote replica or peer: longer when this machine cannot run the cell (no local fallback).
pub const REMOTE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(8);
/// How long `by_name` keeps retrying the remote side when this machine cannot run the cell.
pub const REMOTE_RETRY_FOR: std::time::Duration = std::time::Duration::from_secs(30);

/// The wait before the next round when the cell is pinned away from here: 1 s, inside `REMOTE_RETRY_FOR`.
pub fn remote_wait(start: std::time::Instant) -> Option<std::time::Duration> {
    let w = std::time::Duration::from_secs(1);
    (start.elapsed() + w < REMOTE_RETRY_FOR).then_some(w)
}

#[cfg(any(feature = "client", feature = "blocking"))]
pub(crate) fn unreachable<A: Api>(find: Option<FindError>, tried: Vec<String>, last: crate::WireError) -> crate::WireError {
    crate::WireError::Unreachable(Box::new(Unreachable { api: A::NAME.into(), major: major::<A>(), find, tried, cause: format!("{last:?}") }))
}

/// Ask net.find (tokio). None: no finder answered.
#[cfg(feature = "client")]
pub async fn find_async(name: &str, major: u16) -> Option<Result<FindReply, FindError>> {
    for a in finders() {
        let Ok(mut c) = crate::Client::<NetFind>::connect_opts(a, mesh_token(), false, crate::DEADLINE).await else { continue };
        c.deadline = FIND_WAIT;
        if let Ok(r) = c.call::<Find>(&FindReq { name: name.into(), major }).await {
            return Some(r);
        }
    }
    None
}

/// Ask net.find (std threads). None: no finder answered.
#[cfg(feature = "blocking")]
pub fn find_blocking(name: &str, major: u16) -> Option<Result<FindReply, FindError>> {
    for a in finders() {
        let Ok(c) = crate::blocking::Client::<NetFind>::connect_opts(a, mesh_token(), false, crate::DEADLINE) else { continue };
        c.set_deadline(FIND_WAIT);
        if let Ok(r) = c.call::<Find>(&FindReq { name: name.into(), major }) {
            return Some(r);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::retry_wait;
    use std::time::{Duration, Instant};

    #[test]
    fn retries_back_off_and_stop_inside_the_budget() {
        std::env::remove_var("CE_WIRE_RETRY_MS");
        let now = Instant::now();
        let waits: Vec<_> = (0..6).map(|r| retry_wait(now, r).unwrap().as_millis()).collect();
        assert_eq!(waits, [250, 500, 1000, 2000, 2000, 2000]);
        let late = now - Duration::from_millis(11_000);
        assert_eq!(retry_wait(late, 0), Some(Duration::from_millis(250)));
        assert_eq!(retry_wait(late, 3), None, "a 2 s wait would end past the 12 s budget");
        std::env::set_var("CE_WIRE_RETRY_MS", "0");
        assert_eq!(retry_wait(now, 0), None, "0 turns retrying off");
        std::env::remove_var("CE_WIRE_RETRY_MS");
    }
}
