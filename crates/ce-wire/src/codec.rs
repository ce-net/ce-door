//! Sans-IO half of the client: everything needed to talk ce-wire over ANY byte stream, with no tokio, no sockets, no
//! threads. Builds for wasm32-unknown-unknown (`--no-default-features --features codec`). A browser, a test or a
//! pipe feeds received bytes to a [`Decoder`] and writes the frames the builders return; the handshake, op ids,
//! schema hash and postcard bodies are the same as the tokio client's, so type checking stays end to end.
use crate::{Api, FrameError, Header, Kind, Op, Stream, HEADER, MAX_PAYLOAD};
use serde::{Deserialize, Serialize};

/// First frame on every connection, client to server.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Hello {
    pub api: String,
    pub version: u32,
    pub schema: u64,
    /// ce-cap token bytes; checked by the server's gate.
    pub token: Vec<u8>,
    /// For a door: start the cell on this machine if no process of it runs here.
    pub spawn: bool,
}

/// Server's answer to Hello, and the body of every Err frame.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Refusal {
    /// Hello accepted. `session` keys this connection's datagrams.
    Ok { session: u64 },
    Schema { ours: u64, theirs: u64, api: String },
    Gate(String),
    Right(String),
    UnknownOp(u32),
    /// The door has no such cell on this machine and cannot start it.
    NoCell(String),
    Decode(String),
    Remote(String),
    /// The schema refusal for a wire-2 caller (see [`HelloExt`]): what the door does about it. `update` is
    /// "checking", "updating", "queued #N" (the caller may retry once, waiting), or "caller-stale", "needs a human:
    /// <why>", "unknown: <why>", "rate-limited" (it may not). Appended last: older peers' variant numbers are unchanged,
    /// and an older caller is only ever sent `Schema`.
    SchemaAt { ours: u64, theirs: u64, api: String, update: String },
    /// A caller at an older version of the api, answered through typed adapters (src/adapt.rs),
    /// and this op could not be carried: `op`/`op_name` as the caller knows it, `ours` and
    /// `theirs` the two api versions, `why` the field and the reason. The other ops of the connection keep working.
    /// Appended last, like `SchemaAt`.
    Adapt { api: String, op: u32, op_name: String, ours: u32, theirs: u32, why: AdaptError },
    /// A wire-3 caller whose whole schema differs was let in op by op, and this op's
    /// hash differs: `ours`/`theirs` are the two per-op hashes (`theirs` 0 when the caller's table lacks the op). The
    /// connection stays open and the caller's other ops keep working. Appended last.
    SchemaMismatch { api: String, op: u32, op_name: String, ours: u64, theirs: u64 },
    /// A door's answer to a Hello for `<api>#*`: every name this machine has a process of that api registered under
    /// (`obs.source`, `obs.source#wx.metar`, ...), sorted. Not a refusal: the listing ends the connection. A Hello
    /// for `#*` is answered only by a door that knows instances; an older door refuses it with NoCell. Appended last.
    Instances(Vec<String>),
}

/// Why one value could not be carried between two versions. Carried in [`Refusal::Adapt`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum AdaptError {
    /// A number that fits the newer, wider type but not the older one (`field` path, the value as text).
    Narrow { field: String, value: String },
    /// An enum variant the older version does not have.
    NoVariant { field: String, variant: String },
    /// A value the target version needs and the source does not carry (a required field, a removed op's answer).
    Missing { field: String },
    /// No adapter for this op between these versions: it was removed or changed in a way nobody has written.
    NoPath,
    /// The body did not decode as the version it claimed (`why` from postcard).
    Decode(String),
}


impl Refusal {
    /// A `SchemaAt` whose update is under way: one retry, waiting up to [`DRIFT_WAIT`], can succeed.
    pub fn update_pending(&self) -> bool {
        matches!(self, Refusal::SchemaAt { update, .. } if update == "checking" || update == "updating" || update.starts_with("queued"))
    }
}

/// This crate's wire revision, sent in [`HelloExt`]. 1 = a Hello with nothing after it; 2 = a [`HelloExt`]; 3 = an
/// [`OpTable`] after the [`HelloExt`] (and after `Refusal::Ok` in the answer to a wire-3 Hello).
pub const WIRE: u32 = 3;
/// How long a caller waits on its one retry after a pending `SchemaAt` (an update builds in this time or is queued).
pub const DRIFT_WAIT: std::time::Duration = std::time::Duration::from_secs(120);

/// Written after the Hello in the same frame. postcard decodes a Hello and ignores what follows, so an older door or
/// cell reads a wire-2 Hello unchanged; a wire-2 door reads this to know the caller's revision and its answer wait.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Default)]
pub struct HelloExt {
    pub wire: u32,
    /// How long the caller waits for the Hello answer: a door may hold the Hello this long (minus a margin).
    pub wait_ms: u32,
}

/// Wire 3: `(op id, per-op hash)` for every op and stream the sender knows ([`crate::op_hashes`]), written after the
/// [`HelloExt`] of a Hello and after the `Refusal::Ok` of its answer. A wire-2 peer stops reading before it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct OpTable {
    pub ops: Vec<(u32, u64)>,
}

/// The Hello payload with its [`HelloExt`] and an empty [`OpTable`] (a caller that knows no per-op hashes).
pub fn hello_payload(h: &Hello, wait: std::time::Duration) -> Result<Vec<u8>, String> {
    hello_payload_ops(h, wait, &[])
}

/// The Hello payload: Hello | HelloExt { wire 3, wait_ms } | OpTable { ops }.
pub fn hello_payload_ops(h: &Hello, wait: std::time::Duration, ops: &[(u32, u64)]) -> Result<Vec<u8>, String> {
    let mut p = enc(h)?;
    p.extend(enc(&HelloExt { wire: WIRE, wait_ms: wait.as_millis().min(u32::MAX as u128) as u32 })?);
    p.extend(enc(&OpTable { ops: ops.to_vec() })?);
    Ok(p)
}

/// A Hello payload and its extension (wire 1 when there is none).
pub fn split_hello(p: &[u8]) -> Result<(Hello, HelloExt), String> {
    split_hello_ops(p).map(|(h, e, _)| (h, e))
}

/// A Hello payload, its extension and its op table (empty below wire 3 or when it does not decode).
pub fn split_hello_ops(p: &[u8]) -> Result<(Hello, HelloExt, Vec<(u32, u64)>), String> {
    let (h, rest) = postcard::take_from_bytes::<Hello>(p).map_err(|e| e.to_string())?;
    let Ok((ext, rest)) = postcard::take_from_bytes::<HelloExt>(rest) else { return Ok((h, HelloExt { wire: 1, wait_ms: 0 }, vec![])) };
    let ops = if ext.wire >= 3 { postcard::from_bytes::<OpTable>(rest).map(|t| t.ops).unwrap_or_default() } else { vec![] };
    Ok((h, ext, ops))
}

/// The answer to an accepted Hello: `Refusal::Ok`, then the server's [`OpTable`] when the caller speaks wire 3.
pub fn ok_payload(session: u64, wire: u32, ops: &[(u32, u64)]) -> Vec<u8> {
    let mut p = enc(&Refusal::Ok { session }).unwrap_or_default();
    if wire >= 3 { p.extend(enc(&OpTable { ops: ops.to_vec() }).unwrap_or_default()); }
    p
}

/// The answer to a Hello and, after an `Ok`, the server's op table (empty from a wire-2 server).
pub fn split_answer(p: &[u8]) -> Result<(Refusal, Vec<(u32, u64)>), String> {
    let (r, rest) = postcard::take_from_bytes::<Refusal>(p).map_err(|e| e.to_string())?;
    let ops = if matches!(r, Refusal::Ok { .. }) { postcard::from_bytes::<OpTable>(rest).map(|t| t.ops).unwrap_or_default() } else { vec![] };
    Ok((r, ops))
}

/// The per-op maps for a wire-3 caller whose whole schema `A` does not take: `Some((peer, ours))` when at least one
/// of its ops has the same hash here (a caller that shares no op is refused at Hello, as before), else `None`.
pub fn per_op_admit<A: Api>(peer: Vec<(u32, u64)>) -> Option<(std::collections::HashMap<u32, u64>, std::collections::HashMap<u32, u64>)> {
    let ours: std::collections::HashMap<u32, u64> = crate::op_hashes::<A>().into_iter().collect();
    let peer: std::collections::HashMap<u32, u64> = peer.into_iter().collect();
    peer.iter().any(|(op, h)| ours.get(op) == Some(h)).then_some((peer, ours))
}

/// ` ops=<id>:<hex>,...` for a REGISTER line (empty when the api declares no ops).
pub fn ops_field<A: Api>() -> String {
    let v = crate::op_hashes::<A>();
    if v.is_empty() { return String::new() }
    format!(" ops={}", v.iter().map(|(i, h)| format!("{i}:{h:016x}")).collect::<Vec<_>>().join(","))
}

/// For a server that let a wire-3 caller in op by op: `None` when op `op` may be dispatched, else the refusal
/// (`UnknownOp` when the server has no such op, `SchemaMismatch` when the two hashes differ).
pub fn per_op_check<A: Api>(peer: &std::collections::HashMap<u32, u64>, ours: &std::collections::HashMap<u32, u64>, op: u32) -> Option<Refusal> {
    let Some(&o) = ours.get(&op) else { return Some(Refusal::UnknownOp(op)) };
    let t = peer.get(&op).copied().unwrap_or(0);
    (t != o).then(|| Refusal::SchemaMismatch {
        api: A::NAME.into(), op, op_name: A::OPS.iter().find(|s| s.id == op).map_or("", |s| s.name).into(), ours: o, theirs: t,
    })
}

pub fn frame(kind: Kind, req_id: u64, op: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(HEADER + payload.len());
    v.extend_from_slice(&Header { len: payload.len() as u32, kind, req_id, op }.encode());
    v.extend_from_slice(payload);
    v
}

fn enc<T: Serialize>(v: &T) -> Result<Vec<u8>, String> {
    postcard::to_stdvec(v).map_err(|e| e.to_string())
}

/// The first frame to send for API `A` (`spawn`: ask a door to start the cell).
pub fn hello_frame<A: Api>(token: Vec<u8>, spawn: bool) -> Result<Vec<u8>, String> {
    let h = Hello { api: A::NAME.into(), version: A::VERSION, schema: A::SCHEMA, token, spawn };
    Ok(frame(Kind::Hello, 0, 0, &enc(&h)?))
}

/// A request frame for op `O` with id `req_id`.
pub fn req_frame<O: Op>(req_id: u64, req: &O::Req) -> Result<Vec<u8>, String> {
    Ok(frame(Kind::Req, req_id, O::ID, &enc(req)?))
}

/// A frame that opens stream `S` as `req_id`.
pub fn sub_frame<S: Stream>(req_id: u64, req: &S::Req) -> Result<Vec<u8>, String> {
    Ok(frame(Kind::Sub, req_id, S::ID, &enc(req)?))
}

/// A frame that stops stream `req_id`.
pub fn end_frame(req_id: u64) -> Vec<u8> {
    frame(Kind::End, req_id, 0, &[])
}

/// One complete frame received.
#[derive(Debug, Clone, PartialEq)]
pub struct Received {
    pub header: Header,
    pub body: Vec<u8>,
}

impl Received {
    /// The answer to Hello: the session key, or why the peer refused.
    pub fn hello_answer(&self) -> Result<u64, Refusal> {
        match postcard::from_bytes::<Refusal>(&self.body) {
            Ok(Refusal::Ok { session }) if self.header.kind == Kind::Hello => Ok(session),
            Ok(r) => Err(r),
            Err(e) => Err(Refusal::Decode(e.to_string())),
        }
    }
    /// The typed answer to a Req: `Resp` decodes to the response, `Err` to the peer's refusal.
    pub fn resp<O: Op>(&self) -> Result<O::Resp, Refusal> {
        match self.header.kind {
            Kind::Resp => postcard::from_bytes(&self.body).map_err(|e| Refusal::Decode(e.to_string())),
            _ => Err(postcard::from_bytes(&self.body).unwrap_or_else(|e| Refusal::Decode(e.to_string()))),
        }
    }
    /// One item of stream `S` (`Item`), or None for End.
    pub fn item<S: Stream>(&self) -> Result<Option<S::Item>, Refusal> {
        match self.header.kind {
            Kind::Item => postcard::from_bytes(&self.body).map(Some).map_err(|e| Refusal::Decode(e.to_string())),
            Kind::End => Ok(None),
            _ => Err(postcard::from_bytes(&self.body).unwrap_or_else(|e| Refusal::Decode(e.to_string()))),
        }
    }
}

/// Reassembles frames from arbitrary chunks of a byte stream.
#[derive(Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }
    /// Add received bytes; returns every frame now complete. A protocol error is fatal: close the stream.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Received>, FrameError> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        let mut at = 0;
        while self.buf.len() - at >= HEADER {
            let mut hb = [0u8; HEADER];
            hb.copy_from_slice(&self.buf[at..at + HEADER]);
            let header = Header::decode(&hb)?;
            debug_assert!(header.len <= MAX_PAYLOAD);
            let end = at + HEADER + header.len as usize;
            if self.buf.len() < end {
                break;
            }
            out.push(Received { header, body: self.buf[at + HEADER..end].to_vec() });
            at = end;
        }
        self.buf.drain(..at);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    crate::api! {
        api T = "codec.test", version 1;
        types { pub struct Q { pub n: u32 } pub struct A2 { pub s: String } }
        ops { 1 => Echo(Q) -> A2, needs "codec.test:use"; }
        streams { 2 => Ticks(()) -> stream Q, needs "codec.test:use"; }
    }

    #[test]
    fn frames_roundtrip_in_odd_chunks() {
        let mut wire = hello_frame::<T>(vec![1, 2], true).unwrap();
        wire.extend(req_frame::<Echo>(7, &Q { n: 5 }).unwrap());
        wire.extend(sub_frame::<Ticks>(8, &()).unwrap());
        wire.extend(end_frame(8));
        let mut d = Decoder::new();
        let mut got = Vec::new();
        for c in wire.chunks(3) {
            got.extend(d.push(c).unwrap());
        }
        assert_eq!(got.len(), 4);
        let h: Hello = postcard::from_bytes(&got[0].body).unwrap();
        assert_eq!((h.api.as_str(), h.schema, h.spawn), ("codec.test", T::SCHEMA, true));
        assert_eq!(postcard::from_bytes::<Q>(&got[1].body).unwrap(), Q { n: 5 });
        assert_eq!((got[2].header.kind, got[2].header.op), (Kind::Sub, 2));
        assert_eq!(got[3].header.kind, Kind::End);
    }

    #[test]
    fn typed_answers_and_refusals() {
        let ok = Received { header: Header { len: 0, kind: Kind::Hello, req_id: 0, op: 0 }, body: postcard::to_stdvec(&Refusal::Ok { session: 9 }).unwrap() };
        assert_eq!(ok.hello_answer(), Ok(9));
        let no = Received { header: Header { len: 0, kind: Kind::Hello, req_id: 0, op: 0 }, body: postcard::to_stdvec(&Refusal::Schema { ours: 1, theirs: 2, api: "x".into() }).unwrap() };
        assert!(matches!(no.hello_answer(), Err(Refusal::Schema { .. })));
    }

    #[test]
    fn a_wire2_hello_reads_the_same_to_an_old_peer() {
        let h = Hello { api: "x".into(), version: 1, schema: 7, token: vec![1, 2], spawn: true };
        let p = hello_payload(&h, std::time::Duration::from_secs(120)).unwrap();
        let old: Hello = postcard::from_bytes(&p).unwrap();
        assert_eq!((old.api.as_str(), old.schema, old.spawn), ("x", 7, true));
        let (h2, ext) = split_hello(&p).unwrap();
        assert_eq!((h2.schema, ext), (7, HelloExt { wire: WIRE, wait_ms: 120_000 }));
        let (_, ext1) = split_hello(&postcard::to_stdvec(&h).unwrap()).unwrap();
        assert_eq!(ext1.wire, 1);
        // the old variants keep their numbers: Schema is still variant 1
        assert_eq!(postcard::to_stdvec(&Refusal::Schema { ours: 0, theirs: 0, api: String::new() }).unwrap()[0], 1);
        let r = Received { header: Header { len: 0, kind: Kind::Resp, req_id: 1, op: 1 }, body: postcard::to_stdvec(&A2 { s: "hi".into() }).unwrap() };
        assert_eq!(r.resp::<Echo>(), Ok(A2 { s: "hi".into() }));
        let e = Received { header: Header { len: 0, kind: Kind::Err, req_id: 1, op: 1 }, body: postcard::to_stdvec(&Refusal::Right("r".into())).unwrap() };
        assert_eq!(e.resp::<Echo>(), Err(Refusal::Right("r".into())));
        let bad = [0u8, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(Decoder::new().push(&bad), Err(FrameError::BadKind(9)));
    }
}
