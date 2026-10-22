//! ce-wire: typed calls between ce-net apps.
//!
//! The core (this file) is `no_std` and allocation-free so an MCU shares the same frame and op types as the
//! daemon. `std` adds the tokio [`Client`] and [`Server`]. Design: `../DESIGN.md`.
#![cfg_attr(not(any(feature = "client", feature = "blocking", feature = "codec")), no_std)]

extern crate self as ce_wire;
pub use postcard;
pub use serde;

#[cfg(any(feature = "client", feature = "blocking", feature = "codec"))]
mod codec;
#[cfg(any(feature = "client", feature = "blocking", feature = "codec"))]
pub use codec::*;
#[cfg(any(feature = "client", feature = "blocking"))]
mod proto;
#[cfg(any(feature = "client", feature = "blocking"))]
pub use proto::*;
/// Std-thread client and server, no tokio (feature `blocking`): same frames, Hello, rights, sessions, streams.
#[cfg(feature = "blocking")]
pub mod blocking;
#[cfg(any(feature = "client", feature = "blocking", feature = "codec"))]
pub mod provider;
#[cfg(any(feature = "client", feature = "blocking"))]
pub mod adapt;
mod lock;
pub use lock::check_lock;
#[cfg(feature = "client")]
mod net;
#[cfg(feature = "client")]
pub use net::*;
#[cfg(feature = "client")]
mod link;
#[cfg(feature = "client")]
pub use link::*;
/// The private networks a door listens on and finds peers through: ce-scale, tailscale, netbird, zerotier, static.
#[cfg(feature = "server")]
pub mod underlay;
#[cfg(all(feature = "server", unix))]
mod door;
#[cfg(all(feature = "server", unix))]
pub use door::*;
/// Find-or-spawn by name: the `net.find` API and the typed [`find::Unreachable`] error.
#[cfg(any(feature = "client", feature = "blocking", feature = "codec"))]
pub mod find;
#[cfg(any(feature = "client", feature = "blocking"))]
mod apoptosis;
#[cfg(any(feature = "client", feature = "blocking"))]
pub use apoptosis::*;
#[cfg(any(feature = "client", feature = "blocking"))]
mod name;
#[cfg(any(feature = "client", feature = "blocking"))]
pub use name::*;

/// Bytes in a frame header: `u32 len | u8 kind | u64 req_id | u32 op`, little-endian.
pub const HEADER: usize = 17;
/// Largest payload a peer accepts (16 MiB). Larger is a protocol error, the connection is closed.
pub const MAX_PAYLOAD: u32 = 16 << 20;
/// Largest UDP datagram payload on net.mesh nm0 (MTU 1280).
pub const MAX_DATAGRAM: usize = 1200;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Hello = 0,
    Req = 1,
    Resp = 2,
    Err = 3,
    Datagram = 4,
    /// Client -> server: open stream `op` with this req_id.
    Sub = 5,
    /// Server -> client: one item of stream req_id.
    Item = 6,
    /// Client -> server: stop stream req_id. Server -> client: the stream ended normally.
    End = 7,
}

impl Kind {
    pub const fn from_u8(b: u8) -> Option<Kind> {
        match b {
            0 => Some(Kind::Hello),
            1 => Some(Kind::Req),
            2 => Some(Kind::Resp),
            3 => Some(Kind::Err),
            4 => Some(Kind::Datagram),
            5 => Some(Kind::Sub),
            6 => Some(Kind::Item),
            7 => Some(Kind::End),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Payload bytes after the header.
    pub len: u32,
    pub kind: Kind,
    /// Request id, echoed in the Resp/Err. For a Datagram: the sender's sequence number.
    pub req_id: u64,
    /// `Op::ID`.
    pub op: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    BadKind(u8),
    TooBig(u32),
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER] {
        let mut b = [0u8; HEADER];
        b[0..4].copy_from_slice(&self.len.to_le_bytes());
        b[4] = self.kind as u8;
        b[5..13].copy_from_slice(&self.req_id.to_le_bytes());
        b[13..17].copy_from_slice(&self.op.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8; HEADER]) -> Result<Header, FrameError> {
        let len = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        if len > MAX_PAYLOAD {
            return Err(FrameError::TooBig(len));
        }
        let kind = Kind::from_u8(b[4]).ok_or(FrameError::BadKind(b[4]))?;
        let mut r = [0u8; 8];
        r.copy_from_slice(&b[5..13]);
        Ok(Header { len, kind, req_id: u64::from_le_bytes(r), op: u32::from_le_bytes([b[13], b[14], b[15], b[16]]) })
    }
}

/// An app's API: its name, version and the hash of its whole definition (ops + type token text).
pub trait Api: 'static {
    const NAME: &'static str;
    const VERSION: u32;
    const SCHEMA: u64;
    /// Every right an op or stream of this API needs, in declaration order (duplicates possible). A gate grants a
    /// caller the subset its ce-cap covers.
    const RIGHTS: &'static [&'static str] = &[];
    /// Older schema hashes a server still answers: only when the change since then added ops or types and changed
    /// none (an old client never sends what it does not know). Declared with `accepts [..]` in [`api!`].
    const ACCEPTS: &'static [u64] = &[];
    /// Every op and stream as declared, for the per-op hash ([`op_hashes`]).
    const OPS: &'static [OpShape] = &[];
    /// The token text of every type item in `types {}`, for the per-op hash.
    const TYPES: &'static [&'static str] = &[];
}

/// One op or stream line of an [`api!`], as token text.
#[derive(Debug, Clone, Copy)]
pub struct OpShape { pub id: u32, pub name: &'static str, pub req: &'static str, pub resp: &'static str, pub stream: bool }

/// Identifiers in token text, string literals skipped (doc comments are `#[doc = "..."]` after `stringify!`).
fn idents(s: &str) -> Vec<&str> {
    let (b, mut out, mut i) = (s.as_bytes(), vec![], 0);
    while i < b.len() {
        let c = b[i];
        if c == b'"' {
            i += 1;
            while i < b.len() && b[i] != b'"' { i += if b[i] == b'\\' { 2 } else { 1 }; }
            i += 1;
        } else if c.is_ascii_alphabetic() || c == b'_' {
            let st = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') { i += 1; }
            out.push(&s[st..i]);
        } else {
            i += 1;
        }
    }
    out
}

/// The name a type item declares: the identifier after `struct`, `enum`, `type` or `union`.
fn item_name(item: &str) -> Option<&str> {
    let v = idents(item);
    v.iter().position(|w| matches!(*w, "struct" | "enum" | "type" | "union")).and_then(|i| v.get(i + 1).copied())
}

/// Tokens of `stringify!` text: identifiers and numbers, string literals whole, `::` and `->` as one, any other
/// punctuation one char each; whitespace dropped.
fn tokens(s: &str) -> Vec<&str> {
    let (b, mut out, mut i) = (s.as_bytes(), vec![], 0);
    while i < b.len() {
        let (c, st) = (b[i], i);
        if c.is_ascii_whitespace() { i += 1; continue; }
        if c == b'"' {
            i += 1;
            while i < b.len() && b[i] != b'"' { i += if b[i] == b'\\' { 2 } else { 1 }; }
            i = (i + 1).min(b.len());
        } else if c.is_ascii_alphanumeric() || c == b'_' {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') { i += 1; }
        } else if (c == b':' && b.get(i + 1) == Some(&b':')) || (c == b'-' && b.get(i + 1) == Some(&b'>')) {
            i += 2;
        } else {
            i += 1;
        }
        out.push(&s[st..i]);
    }
    out
}

/// The tokens of one type item that decide its postcard bytes. Dropped: `#[doc]` attributes, `pub` / `pub(..)`, the
/// item's own name, field names, and enum variant names (postcard writes fields in order and a variant as its index).
/// Kept: field and variant order, every field type, generic arguments and other attributes (`#[serde(..)]` can change bytes).
fn shape_tokens(item: &str) -> Vec<&str> {
    let t = tokens(item);
    let mut out: Vec<&str> = vec![];
    let (mut i, mut depth, mut is_enum, mut named_next) = (0, 0i32, false, false);
    while i < t.len() {
        let w = t[i];
        // #[doc = ".."]: skip through the matching ]
        if w == "#" && t.get(i + 1) == Some(&"[") && t.get(i + 2) == Some(&"doc") {
            let mut d = 0;
            while i < t.len() {
                if t[i] == "[" { d += 1; }
                if t[i] == "]" { d -= 1; if d == 0 { break; } }
                i += 1;
            }
            i += 1;
            continue;
        }
        if w == "pub" {
            i += 1;
            if t.get(i) == Some(&"(") { while i < t.len() && t[i] != ")" { i += 1; } i += 1; }
            continue;
        }
        if depth == 0 && (w == "struct" || w == "enum") {
            is_enum = w == "enum";
            named_next = true;
            out.push(w);
            i += 1;
            continue;
        }
        if named_next { named_next = false; out.push("_"); i += 1; continue; }
        let starts = matches!(out.last(), Some(&"{") | Some(&",") | Some(&"("));
        let ident = w.as_bytes()[0].is_ascii_alphabetic() || w.starts_with('_');
        if ident && matches!(out.last(), Some(&"{") | Some(&",")) && t.get(i + 1) == Some(&":") { i += 2; continue; }
        if ident && is_enum && depth == 1 && starts { out.push("v"); i += 1; continue; }
        match w { "{" | "(" | "[" => depth += 1, "}" | ")" | "]" => depth -= 1, _ => {} }
        out.push(w);
        i += 1;
    }
    out
}

/// The per-op schema hash: FNV-1a 64 of the api name, the op id, the request and response
/// (`stream` for a stream) and every type of `types {}` they reach, transitively, in first-reached order, each written
/// as [`shape_tokens`] with a type name replaced by `#<its reach index>`. So a doc comment, a field, variant, type or op
/// rename (identical postcard bytes) keeps the hash; a type, order or attribute change moves it, and only for the ops
/// that carry it. The version and the right are not in it (neither changes a byte of the body).
pub fn shape_hash<'a>(api: &str, types: &[&'a str], o: &OpShape) -> u64 {
    let named: std::collections::BTreeMap<&'a str, &'a str> = types.iter().filter_map(|t| item_name(t).map(|n| (n, *t))).collect();
    let mut order: Vec<&'a str> = vec![];
    let emit = |toks: Vec<&'a str>, order: &mut Vec<&'a str>, text: &mut String| {
        for w in toks {
            match named.get_key_value(w) {
                Some((k, _)) => {
                    let n = order.iter().position(|x| x == k).unwrap_or_else(|| { order.push(k); order.len() - 1 });
                    text.push_str(&format!(" #{n}"));
                }
                None => { text.push(' '); text.push_str(w); }
            }
        }
    };
    let mut text = format!("{api}|{}", o.id);
    emit(tokens(o.req), &mut order, &mut text);
    text.push_str(if o.stream { " ->stream" } else { " ->" });
    emit(tokens(o.resp), &mut order, &mut text);
    let mut k = 0;
    while k < order.len() {
        text.push('|');
        emit(shape_tokens(named[order[k]]), &mut order, &mut text);
        k += 1;
    }
    fnv64(text.as_bytes())
}

/// `(op id, per-op hash)` for every op and stream of `A`: the table a wire-3 Hello carries.
pub fn op_hashes<A: Api>() -> Vec<(u32, u64)> {
    A::OPS.iter().map(|o| (o.id, shape_hash(A::NAME, A::TYPES, o))).collect()
}

/// The per-op hash of one op (0 when the api declares no shapes).
pub fn op_hash<O: Op>() -> u64 {
    <O::Api as Api>::OPS.iter().find(|s| s.id == O::ID && !s.stream).map_or(0, |s| shape_hash(<O::Api as Api>::NAME, <O::Api as Api>::TYPES, s))
}

/// True when a peer saying `schema` may talk to a server of `A`: the same hash, or one `A` lists in `ACCEPTS`.
pub fn schema_ok<A: Api>(schema: u64) -> bool {
    schema == A::SCHEMA || A::ACCEPTS.contains(&schema)
}

/// One typed operation of an [`Api`]. A client can only send `Req` and only get `Resp` back.
pub trait Op: 'static {
    type Api: Api;
    const ID: u32;
    const NAME: &'static str;
    /// The ce-cap right a caller must hold to call this op.
    const RIGHT: &'static str;
    /// How long a client waits for this op's answer, from `deadline_ms N` in `api!`. None: the client's own deadline
    /// (`DEADLINE`, 1 s, unless the caller set another). A client waits the longer of the two. Not in the schema hash:
    /// it changes no byte on the wire.
    const DEADLINE_MS: Option<u64> = None;
    type Req: serde::Serialize + serde::de::DeserializeOwned;
    type Resp: serde::Serialize + serde::de::DeserializeOwned;
}

/// How long a client with deadline `client` waits for op `O`: the longer of the two.
pub fn op_deadline<O: Op>(client: core::time::Duration) -> core::time::Duration {
    O::DEADLINE_MS.map(core::time::Duration::from_millis).map_or(client, |d| d.max(client))
}

#[doc(hidden)]
#[macro_export]
macro_rules! __deadline_ms {
    () => { None };
    ($ms:literal) => { Some($ms) };
}

/// A typed server-push stream of an [`Api`]: one `Req` opens it, then the server sends `Item`s until either side
/// ends it. Pattern for UI state: first item = full snapshot, then deltas (or full states, latest wins).
/// Stream ids share the op id space.
pub trait Stream: 'static {
    type Api: Api;
    const ID: u32;
    const NAME: &'static str;
    const RIGHT: &'static str;
    type Req: serde::Serialize + serde::de::DeserializeOwned;
    type Item: serde::Serialize + serde::de::DeserializeOwned;
}

/// FNV-1a 64, const so the schema hash is computed at compile time.
pub const fn fnv64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut i = 0;
    while i < bytes.len() {
        h ^= bytes[i] as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
        i += 1;
    }
    h
}

/// Declares an API: its types and its ops. The schema hash covers the token text of every type and op line, so
/// any change to a field, a type or an op changes the hash and a mismatched peer is refused at connect.
///
/// ```ignore
/// ce_wire::api! {
///     api ServoBus = "servo.bus", version 1;
///     types {
///         pub struct GoalReq { pub id: u8, pub counts: i16 }
///         pub struct GoalAck { pub accepted: bool }
///     }
///     ops {
///         1 => Goal(GoalReq) -> GoalAck, needs "servo.goal";
///     }
/// }
/// ```
#[macro_export]
macro_rules! api {
    (
        api $api:ident = $name:literal, version $ver:literal $(, accepts [ $($acc:literal),* $(,)? ])? ;
        types { $($ty:item)* }
        ops { $( $id:literal => $op:ident ( $req:ty ) -> $resp:ty , needs $right:literal $(, deadline_ms $dl:literal)? ; )* }
        $( streams { $( $sid:literal => $sop:ident ( $sreq:ty ) -> stream $item:ty , needs $sright:literal ; )* } )?
    ) => {
        $(
            #[derive($crate::serde::Serialize, $crate::serde::Deserialize, Clone, PartialEq, Debug)]
            #[serde(crate = "ce_wire::serde")]
            $ty
        )*

        pub struct $api;
        impl $crate::Api for $api {
            const NAME: &'static str = $name;
            const VERSION: u32 = $ver;
            const SCHEMA: u64 = $crate::fnv64(concat!(
                $name, "/", stringify!($ver), "|", stringify!($($ty)*),
                $( "|", stringify!($id), " ", stringify!($op), "(", stringify!($req), ")->", stringify!($resp), " ", $right, )*
                $($( "|", stringify!($sid), " ", stringify!($sop), "(", stringify!($sreq), ")->stream ", stringify!($item), " ", $sright, )*)?
            ).as_bytes());
            const RIGHTS: &'static [&'static str] = &[$($right,)* $($($sright,)*)?];
            const ACCEPTS: &'static [u64] = &[$($($acc,)*)?];
            const OPS: &'static [$crate::OpShape] = &[
                $( $crate::OpShape { id: $id, name: stringify!($op), req: stringify!($req), resp: stringify!($resp), stream: false }, )*
                $($( $crate::OpShape { id: $sid, name: stringify!($sop), req: stringify!($sreq), resp: stringify!($item), stream: true }, )*)?
            ];
            const TYPES: &'static [&'static str] = &[$( stringify!($ty), )*];
        }

        $(
            pub struct $op;
            impl $crate::Op for $op {
                type Api = $api;
                const ID: u32 = $id;
                const NAME: &'static str = stringify!($op);
                const RIGHT: &'static str = $right;
                const DEADLINE_MS: Option<u64> = $crate::__deadline_ms!($($dl)?);
                type Req = $req;
                type Resp = $resp;
            }
        )*

        $($(
            pub struct $sop;
            impl $crate::Stream for $sop {
                type Api = $api;
                const ID: u32 = $sid;
                const NAME: &'static str = stringify!($sop);
                const RIGHT: &'static str = $sright;
                type Req = $sreq;
                type Item = $item;
            }
        )*)?
    };
}

/// Instance names. Many cells serve one api:
/// `wx.metar`, `wx.smhi`, ... all serve `obs.source` v1, so one fuser binary calls every source. Each registers as
/// `<api>#<name>` (`obs.source#wx.metar`). A Hello for `obs.source#wx.metar` reaches only that instance; a Hello
/// for the bare `obs.source` reaches any of them (and any unnamed `obs.source`). The schema hash stays the api's.
pub const INSTANCE_SEP: char = '#';

/// `obs.source` + `wx.metar` -> `obs.source#wx.metar`; an empty name gives the bare api.
pub fn instance_key(api: &str, name: &str) -> String {
    if name.is_empty() { api.to_string() } else { format!("{api}{INSTANCE_SEP}{name}") }
}

/// The api part of a registered name: `obs.source#wx.metar` -> `obs.source`; a bare api is itself.
pub fn base_api(key: &str) -> &str {
    key.split_once(INSTANCE_SEP).map_or(key, |(a, _)| a)
}

/// The instance part: `obs.source#wx.metar` -> `Some("wx.metar")`; a bare api -> None.
pub fn instance_of(key: &str) -> Option<&str> {
    key.split_once(INSTANCE_SEP).map(|(_, n)| n).filter(|n| !n.is_empty())
}

/// A name a cell may register under: a non-empty api, and at most one non-empty instance with no whitespace.
pub fn valid_key(key: &str) -> bool {
    let ok = |s: &str| !s.is_empty() && !s.contains(char::is_whitespace) && !s.contains(INSTANCE_SEP) && !s.contains(['/', '\\']) && !s.starts_with('.');
    match key.split_once(INSTANCE_SEP) {
        Some((a, n)) => ok(a) && ok(n),
        None => ok(key),
    }
}

/// True when a Hello naming `hello_api` is for API `A`: the bare name or any instance of it.
pub fn hello_is<A: Api>(hello_api: &str) -> bool {
    base_api(hello_api) == A::NAME
}

/// A line of a list file with its comment removed: `#` starts a comment at the line start or after whitespace, so
/// `obs.source#wx.metar` survives in cells.index and the door's autostart file.
pub fn strip_comment(line: &str) -> &str {
    let b = line.as_bytes();
    let cut = (0..b.len()).find(|&i| b[i] == b'#' && (i == 0 || b[i - 1].is_ascii_whitespace())).unwrap_or(b.len());
    &line[..cut]
}

#[cfg(test)]
mod instance_tests {
    use super::*;
    #[test]
    fn keys() {
        assert_eq!(instance_key("obs.source", "wx.metar"), "obs.source#wx.metar");
        assert_eq!(instance_key("obs.source", ""), "obs.source");
        assert_eq!(base_api("obs.source#wx.metar"), "obs.source");
        assert_eq!(base_api("obs.source"), "obs.source");
        assert_eq!(instance_of("obs.source#wx.metar"), Some("wx.metar"));
        assert_eq!(instance_of("obs.source"), None);
        assert!(valid_key("obs.source#wx.metar") && valid_key("obs.source"));
        assert!(!valid_key("obs.source#") && !valid_key("#x") && !valid_key("a#b#c") && !valid_key("a#../x"));
        assert_eq!(strip_comment("obs.source#wx.metar https://x wx-metar # the METAR source"), "obs.source#wx.metar https://x wx-metar ");
        assert_eq!(strip_comment("# all comment"), "");
        assert_eq!(strip_comment("a.b"), "a.b");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod old { crate::api! { api T = "accepts.test", version 1; types { pub struct A { pub x: u8 } } ops { 1 => One(A) -> A, needs "t:one"; } } }
    mod new { crate::api! { api T = "accepts.test", version 1, accepts [0x1234]; types { pub struct A { pub x: u8 } } ops { 1 => One(A) -> A, needs "t:one"; 2 => Two(A) -> A, needs "t:one"; } } }

    #[test]
    fn accepts_lists_older_schemas_and_keeps_the_hash() {
        // accepts does not enter the hash; a server takes its own hash and the listed ones, nothing else.
        assert_ne!(old::T::SCHEMA, new::T::SCHEMA);
        assert!(schema_ok::<new::T>(new::T::SCHEMA));
        assert!(schema_ok::<new::T>(0x1234));
        assert!(!schema_ok::<new::T>(old::T::SCHEMA));
        assert!(!schema_ok::<old::T>(0x1234));
    }

    #[test]
    fn header_roundtrip() {
        let h = Header { len: 42, kind: Kind::Req, req_id: u64::MAX - 3, op: 7 };
        assert_eq!(Header::decode(&h.encode()), Ok(h));
    }

    #[test]
    fn header_rejects() {
        let mut b = Header { len: 1, kind: Kind::Resp, req_id: 1, op: 1 }.encode();
        b[4] = 9;
        assert_eq!(Header::decode(&b), Err(FrameError::BadKind(9)));
        let b = Header { len: MAX_PAYLOAD + 1, kind: Kind::Resp, req_id: 1, op: 1 }.encode();
        assert_eq!(Header::decode(&b), Err(FrameError::TooBig(MAX_PAYLOAD + 1)));
    }

    mod v1 { crate::api! { api T = "perop.test", version 1;
        types { pub struct Inner { pub a: u8 } pub struct R1 { pub i: Vec<Inner> } pub struct R2 { pub b: bool } pub struct Lone { pub z: u8 } }
        ops { 1 => One(R1) -> R2, needs "t:x"; 2 => Two(()) -> R2, needs "t:x"; } } }
    // Inner gained a field (One reaches it through Vec<R1.i>); Lone changed (nobody reaches it); Two's right changed
    mod v2 { crate::api! { api T = "perop.test", version 2;
        types { pub struct Inner { pub a: u8, pub c: u8 } pub struct R1 { pub i: Vec<Inner> } pub struct R2 { pub b: bool } pub struct Lone { pub z: u16 } }
        ops { 1 => One(R1) -> R2, needs "t:x"; 2 => Two(()) -> R2, needs "t:y"; } } }
    // v1 with identical postcard bytes: docs added, every type, field and op renamed, an enum's variants renamed
    mod v3 { crate::api! { api T = "perop.test", version 3;
        types {
            /// one row
            pub struct Row { /// the only field
                pub alpha: u8 }
            pub struct Req { pub rows: Vec<Row> }
            pub struct Ans { pub yes: bool }
            pub struct Lone { pub z: u8 }
            pub enum E1 { A(u8), B { x: String } }
        }
        ops { 1 => First(Req) -> Ans, needs "t:x"; 2 => Second(()) -> Ans, needs "t:x"; 3 => Third(E1) -> (), needs "t:x"; } } }
    mod v4 { crate::api! { api T = "perop.test", version 4;
        types { pub enum E2 { Other(u8), Name { y: String } } pub enum E3 { B { x: String }, A(u8) } }
        ops { 3 => Third(E2) -> (), needs "t:x"; 4 => Fourth(E3) -> (), needs "t:x"; } } }

    #[test]
    fn per_op_hash_ignores_what_postcard_ignores() {
        assert_eq!(op_hash::<v1::One>(), op_hash::<v3::First>(), "docs and type, field and op names change no byte");
        assert_eq!(op_hash::<v1::Two>(), op_hash::<v3::Second>());
        assert_eq!(op_hash::<v3::Third>(), op_hash::<v4::Third>(), "variant names change no byte");
        let e3 = shape_hash("perop.test", <v4::T as Api>::TYPES, &OpShape { id: 3, name: "x", req: "E3", resp: "()", stream: false });
        assert_ne!(op_hash::<v4::Third>(), e3, "variant order changes the index on the wire");
        assert_eq!(shape_tokens(r#"#[doc = "d"] pub struct X { #[doc = "f"] pub a: Option<Y>, pub(crate) b: u8 }"#), vec!["struct", "_", "{", "Option", "<", "Y", ">", ",", "u8", "}"]);
        assert_eq!(shape_tokens("pub enum E { A(u8), B { x: std::string::String }, C }"), vec!["enum", "_", "{", "v", "(", "u8", ")", ",", "v", "{", "std", "::", "string", "::", "String", "}", ",", "v", "}"]);
    }

    #[test]
    fn per_op_hash_covers_only_what_the_op_reaches() {
        assert_ne!(v1::T::SCHEMA, v2::T::SCHEMA);
        assert_ne!(op_hash::<v1::One>(), op_hash::<v2::One>(), "a type reached through Vec<> is covered");
        assert_eq!(op_hash::<v1::Two>(), op_hash::<v2::Two>(), "unreached type, version and right do not count");
        assert_eq!(op_hashes::<v1::T>(), vec![(1, op_hash::<v1::One>()), (2, op_hash::<v1::Two>())]);
        assert_eq!(idents(r#"#[doc = "uses Lone"] pub struct X { a: Option<Y> }"#), vec!["doc", "pub", "struct", "X", "a", "Option", "Y"]);
    }
}
