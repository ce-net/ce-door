//! What the tokio and the blocking (std thread) implementations share: Hello, Refusal, errors, Caller, frames.
pub use crate::codec::{frame, Hello, Refusal};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Default deadline per call: net.mesh failover stalls 0.84-1.9 s, so a call waits 1 s, then the caller reconnects.
pub const DEADLINE: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq)]
pub enum WireError {
    Timeout,
    Closed,
    Io(String),
    Refused(Refusal),
    Decode(String),
    /// `by_name` tried the local door, net.find's replicas, the mesh peers and a local spawn: nothing answered. The
    /// app shows this (which cell, which dependency failed, why) instead of "cannot be reached".
    Unreachable(Box<crate::find::Unreachable>),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Unreachable(u) => write!(f, "{u}"),
            _ => write!(f, "{self:?}"),
        }
    }
}
impl std::error::Error for WireError {}

pub(crate) fn io(e: std::io::Error) -> WireError {
    WireError::Io(e.to_string())
}

/// Who is calling, as the gate decided from the Hello token.
#[derive(Debug, Clone)]
pub struct Caller {
    pub name: String,
    pub rights: Vec<String>,
}

/// A `ce-cap` `path_prefix` caveat reaches a cell as this entry in [`Caller::rights`] (so `Caller` keeps its two fields).
pub const PATH_PREFIX_RIGHT: &str = "caveat:path_prefix=";

/// One answered call, for [`Server::audit`]: built after the reply went out, so an observer never slows the caller.
/// `grant`: the `grant:<hex>` entry ce-gate puts in the caller's rights (empty when the gate gave none). `ok`: the op
/// answered (a typed `Err` inside the answer is still ok here); else `refusal` is the refusal's kind and text.
#[derive(Debug, Clone, PartialEq)]
pub struct CallRecord {
    pub api: &'static str,
    pub op: u32,
    pub op_name: &'static str,
    pub right: &'static str,
    pub caller: String,
    pub grant: String,
    pub ok: bool,
    pub refusal: String,
    pub us: u64,
}

/// The rights entry that names the grant a caller came in with.
pub const GRANT_RIGHT: &str = "grant:";

/// Every ability of the caller's verified leaf capability reaches the cell as `ability:<ability>` in [`Caller::rights`],
/// so a cell can check rights it cannot list statically (one per tool, per path, ...): see [`Caller::grants`].
pub const ABILITY_RIGHT: &str = "ability:";

impl Caller {
    /// Does a verified ability of the caller cover `needed`? Same rule as ce-cap: equal, `*`, or `domain:*`
    /// covering `domain:<anything>` (the bare parent is not covered).
    pub fn grants(&self, needed: &str) -> bool {
        self.rights.iter().filter_map(|r| r.strip_prefix(ABILITY_RIGHT)).any(|g| {
            g == needed || g == "*" || g.strip_suffix('*').is_some_and(|p| p.ends_with(':') && needed.len() > p.len() && needed.starts_with(p))
        })
    }

    /// The `path_prefix` caveat of the caller's capability: the cell must confine every path it touches under it
    /// (`None` = unconfined). Set by `ce-gate`.
    pub fn path_prefix(&self) -> Option<&str> {
        self.rights.iter().find_map(|r| r.strip_prefix(PATH_PREFIX_RIGHT))
    }

    pub fn has(&self, right: &str) -> bool {
        self.rights.iter().any(|r| r == right || r == "*")
    }
}

/// Callers with an open, gated TCP connection, by session key. Datagrams are accepted only with a live key.
pub type Sessions = Arc<Mutex<HashMap<u64, Caller>>>;

pub(crate) fn session_key() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    static N: AtomicU64 = AtomicU64::new(0);
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(N.fetch_add(1, Ordering::Relaxed));
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
    h.finish() | 1
}


/// The op id -> right table for [`DatagramSocket::recv`]: `rights![Goal, Hold]`.
#[macro_export]
macro_rules! rights {
    ($($op:ty),* $(,)?) => {{
        let mut m = std::collections::HashMap::new();
        $( m.insert(<$op as $crate::Op>::ID, <$op as $crate::Op>::RIGHT); )*
        m
    }};
}
