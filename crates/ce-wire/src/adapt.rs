//! Typed adapters between versions of one api. A server built at version N answers a
//! caller built at an older version: for every op of that older schema it holds two typed functions, `req_up` (the old
//! request to the new one) and `resp_down` (the new answer to the old one). Each is plain Rust over the frozen old types
//! and the current ones, so the compiler checks every conversion; `ce-wire-gen adapt` writes them where the change is
//! mechanical and leaves the rest to be written by hand. An op the older schema has but no adapter covers is refused
//! per call with [`Refusal::Adapt`], naming the op, both versions and what is missing; the other ops keep working.
use crate::{AdaptError, Api, Op, Refusal, Stream};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;

type Conv = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>, AdaptError> + Send + Sync>;

/// One older version of api `A` that a server still answers, with its per-op conversions.
#[derive(Clone)]
pub struct Older {
    pub schema: u64,
    pub version: u32,
    ops: HashMap<u32, (u32, Conv, Conv)>,
    names: HashMap<u32, &'static str>,
    /// old stream id -> (current stream id, req_up, item_down)
    streams: HashMap<u32, (u32, Conv, Conv)>,
    stream_names: HashMap<u32, &'static str>,
}

fn dec<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, AdaptError> {
    postcard::from_bytes(b).map_err(|e| AdaptError::Decode(e.to_string()))
}
fn enc<T: Serialize>(v: &T) -> Result<Vec<u8>, AdaptError> {
    postcard::to_stdvec(v).map_err(|e| AdaptError::Decode(e.to_string()))
}

impl Older {
    /// The older api `Old` (its frozen `api!` block): its schema and version come from the type.
    pub fn of<Old: Api>() -> Self {
        Older { schema: Old::SCHEMA, version: Old::VERSION, ops: HashMap::new(), names: HashMap::new(), streams: HashMap::new(), stream_names: HashMap::new() }
    }

    /// Old op `O` is answered by the current op `N`, through `req_up` and `resp_down`.
    pub fn op<O: Op, N: Op>(
        mut self,
        req_up: impl Fn(O::Req) -> Result<N::Req, AdaptError> + Send + Sync + 'static,
        resp_down: impl Fn(N::Resp) -> Result<O::Resp, AdaptError> + Send + Sync + 'static,
    ) -> Self {
        let up: Conv = Arc::new(move |b| enc(&req_up(dec::<O::Req>(b)?)?));
        let down: Conv = Arc::new(move |b| enc(&resp_down(dec::<N::Resp>(b)?)?));
        self.ops.insert(O::ID, (N::ID, up, down));
        self.names.insert(O::ID, O::NAME);
        self
    }

    /// Old op `O` and current op `N` carry the same bytes (their types did not change): pass them through.
    pub fn same<O: Op, N: Op>(mut self) -> Self {
        let id: Conv = Arc::new(|b| Ok(b.to_vec()));
        self.ops.insert(O::ID, (N::ID, id.clone(), id));
        self.names.insert(O::ID, O::NAME);
        self
    }

    /// Old stream `O` is served by the current stream `N`: its request goes up once, every item comes down.
    pub fn stream<O: Stream, N: Stream>(
        mut self,
        req_up: impl Fn(O::Req) -> Result<N::Req, AdaptError> + Send + Sync + 'static,
        item_down: impl Fn(N::Item) -> Result<O::Item, AdaptError> + Send + Sync + 'static,
    ) -> Self {
        let up: Conv = Arc::new(move |b| enc(&req_up(dec::<O::Req>(b)?)?));
        let down: Conv = Arc::new(move |b| enc(&item_down(dec::<N::Item>(b)?)?));
        self.streams.insert(O::ID, (N::ID, up, down));
        self.stream_names.insert(O::ID, O::NAME);
        self
    }

    /// Old stream `O` and current stream `N` carry the same bytes.
    pub fn same_stream<O: Stream, N: Stream>(mut self) -> Self {
        let id: Conv = Arc::new(|b| Ok(b.to_vec()));
        self.streams.insert(O::ID, (N::ID, id.clone(), id));
        self.stream_names.insert(O::ID, O::NAME);
        self
    }

    /// Old op `O` has no path to the current version: every call of it is refused with [`AdaptError::NoPath`].
    /// Listing it (instead of leaving it out) keeps its name in the refusal.
    pub fn gone<O: Op>(mut self) -> Self {
        self.names.insert(O::ID, O::NAME);
        self
    }
}

/// The adapter a connection uses when its Hello named an older schema. Cheap to clone.
#[derive(Clone)]
pub struct Adapter {
    api: &'static str,
    ours: u32,
    old: Arc<Older>,
}

impl Adapter {
    fn refusal(&self, op: u32, e: AdaptError) -> Refusal {
        let name = self.old.names.get(&op).copied().unwrap_or("?");
        Refusal::Adapt { api: self.api.into(), op, op_name: name.into(), ours: self.ours, theirs: self.old.version, why: e }
    }

    fn stream_refusal(&self, op: u32, e: AdaptError) -> Refusal {
        let name = self.old.stream_names.get(&op).copied().unwrap_or("stream");
        Refusal::Adapt { api: self.api.into(), op, op_name: name.into(), ours: self.ours, theirs: self.old.version, why: e }
    }

    /// An older caller's subscription (old stream id, old request) -> the current stream id and request.
    pub fn sub_in(&self, op: u32, body: &[u8]) -> Result<(u32, Vec<u8>), Refusal> {
        let Some((to, up, _)) = self.old.streams.get(&op) else { return Err(self.stream_refusal(op, AdaptError::NoPath)) };
        up(body).map(|b| (*to, b)).map_err(|e| self.stream_refusal(op, e))
    }

    /// One current item of the caller's stream `op` (its old id) -> the item its version decodes. An item that cannot
    /// be carried ends the stream with this refusal.
    pub fn item_out(&self, op: u32, body: &[u8]) -> Result<Vec<u8>, Refusal> {
        let Some((_, _, down)) = self.old.streams.get(&op) else { return Err(self.stream_refusal(op, AdaptError::NoPath)) };
        down(body).map_err(|e| self.stream_refusal(op, e))
    }

    /// The caller's request frame (old op id, old body) -> the current op id and body.
    pub fn req_in(&self, op: u32, body: &[u8]) -> Result<(u32, Vec<u8>), Refusal> {
        let Some((to, up, _)) = self.old.ops.get(&op) else { return Err(self.refusal(op, AdaptError::NoPath)) };
        up(body).map(|b| (*to, b)).map_err(|e| self.refusal(op, e))
    }

    /// The current answer -> the body the caller's version decodes. `op` is the caller's op id.
    pub fn resp_out(&self, op: u32, body: &[u8]) -> Result<Vec<u8>, Refusal> {
        let Some((_, _, down)) = self.old.ops.get(&op) else { return Err(self.refusal(op, AdaptError::NoPath)) };
        down(body).map_err(|e| self.refusal(op, e))
    }
}

/// An older version of api `A` that a client built at `A` can still call: for every current op, the old op that
/// answers it, `req_down` (current request to the old one) and `resp_up` (the old answer to the current one). The
/// client's half of the adapters; `ce-wire-gen adapt` writes `older_server()` returning one.
#[derive(Clone)]
pub struct OlderServer {
    pub schema: u64,
    pub version: u32,
    /// The old version's per-op hashes (2.1): how a wire-3 server's op table is recognised, and what the client's
    /// Hello says when it talks to that server as the old version.
    pub table: Vec<(u32, u64)>,
    ops: HashMap<u32, (u32, Conv, Conv)>,
    names: HashMap<u32, &'static str>,
    /// current stream id -> (old stream id, req_down, item_up)
    streams: HashMap<u32, (u32, Conv, Conv)>,
}

impl OlderServer {
    pub fn of<Old: Api>() -> Self {
        let mut table = crate::op_hashes::<Old>();
        table.sort_unstable();
        OlderServer { schema: Old::SCHEMA, version: Old::VERSION, table, ops: HashMap::new(), names: HashMap::new(), streams: HashMap::new() }
    }

    /// Current op `N` is answered by the old server's op `O`.
    pub fn op<N: Op, O: Op>(
        mut self,
        req_down: impl Fn(N::Req) -> Result<O::Req, AdaptError> + Send + Sync + 'static,
        resp_up: impl Fn(O::Resp) -> Result<N::Resp, AdaptError> + Send + Sync + 'static,
    ) -> Self {
        let down: Conv = Arc::new(move |b| enc(&req_down(dec::<N::Req>(b)?)?));
        let up: Conv = Arc::new(move |b| enc(&resp_up(dec::<O::Resp>(b)?)?));
        self.ops.insert(N::ID, (O::ID, down, up));
        self.names.insert(N::ID, N::NAME);
        self
    }

    /// Same bytes both sides.
    pub fn same<N: Op, O: Op>(mut self) -> Self {
        let id: Conv = Arc::new(|b| Ok(b.to_vec()));
        self.ops.insert(N::ID, (O::ID, id.clone(), id));
        self.names.insert(N::ID, N::NAME);
        self
    }

    /// Current stream `N` is served by the old server's stream `O`.
    pub fn stream<N: Stream, O: Stream>(
        mut self,
        req_down: impl Fn(N::Req) -> Result<O::Req, AdaptError> + Send + Sync + 'static,
        item_up: impl Fn(O::Item) -> Result<N::Item, AdaptError> + Send + Sync + 'static,
    ) -> Self {
        let down: Conv = Arc::new(move |b| enc(&req_down(dec::<N::Req>(b)?)?));
        let up: Conv = Arc::new(move |b| enc(&item_up(dec::<O::Item>(b)?)?));
        self.streams.insert(N::ID, (O::ID, down, up));
        self.names.insert(N::ID, N::NAME);
        self
    }

    pub fn same_stream<N: Stream, O: Stream>(mut self) -> Self {
        let id: Conv = Arc::new(|b| Ok(b.to_vec()));
        self.streams.insert(N::ID, (O::ID, id.clone(), id));
        self.names.insert(N::ID, N::NAME);
        self
    }

    /// Current op `N` does not exist on the old server: every call is refused with [`AdaptError::NoPath`] before it is sent.
    pub fn missing<N: Op>(mut self) -> Self {
        self.names.insert(N::ID, N::NAME);
        self
    }
}

/// The adapter a client connection uses after the server named an older schema it holds.
#[derive(Clone)]
pub struct ServerAdapter {
    api: &'static str,
    ours: u32,
    old: Arc<OlderServer>,
}

impl ServerAdapter {
    pub fn new<A: Api>(old: OlderServer) -> Self {
        ServerAdapter { api: A::NAME, ours: A::VERSION, old: Arc::new(old) }
    }
    pub fn schema(&self) -> u64 {
        self.old.schema
    }
    pub fn version(&self) -> u32 {
        self.old.version
    }
    /// The old version's op table, sent in the Hello when this client talks as the old version.
    pub fn table(&self) -> &[(u32, u64)] {
        &self.old.table
    }
    fn refusal(&self, op: u32, e: AdaptError) -> Refusal {
        let name = self.old.names.get(&op).copied().unwrap_or("?");
        // ours = this client's version, theirs = the server's
        Refusal::Adapt { api: self.api.into(), op, op_name: name.into(), ours: self.ours, theirs: self.old.version, why: e }
    }
    /// Current op id and request body -> the old server's op id and body.
    pub fn req_out(&self, op: u32, body: &[u8]) -> Result<(u32, Vec<u8>), Refusal> {
        let Some((to, down, _)) = self.old.ops.get(&op) else { return Err(self.refusal(op, AdaptError::NoPath)) };
        down(body).map(|b| (*to, b)).map_err(|e| self.refusal(op, e))
    }
    /// The old server's answer to current op `op` -> the body the current type decodes.
    pub fn resp_in(&self, op: u32, body: &[u8]) -> Result<Vec<u8>, Refusal> {
        let Some((_, _, up)) = self.old.ops.get(&op) else { return Err(self.refusal(op, AdaptError::NoPath)) };
        up(body).map_err(|e| self.refusal(op, e))
    }
    /// Current subscription -> the old server's stream id and request.
    pub fn sub_out(&self, op: u32, body: &[u8]) -> Result<(u32, Vec<u8>), Refusal> {
        let Some((to, down, _)) = self.old.streams.get(&op) else { return Err(self.refusal(op, AdaptError::NoPath)) };
        down(body).map(|b| (*to, b)).map_err(|e| self.refusal(op, e))
    }
    /// One item from the old server's stream -> the current item type. `op`: the current stream id.
    pub fn item_in(&self, op: u32, body: &[u8]) -> Result<Vec<u8>, Refusal> {
        let Some((_, _, up)) = self.old.streams.get(&op) else { return Err(self.refusal(op, AdaptError::NoPath)) };
        up(body).map_err(|e| self.refusal(op, e))
    }
}

/// The older servers a client of `A` can still call, by their schema hash.
#[derive(Clone, Default)]
pub struct OlderServers(Arc<HashMap<u64, OlderServer>>);

impl OlderServers {
    pub fn with(mut self, o: OlderServer) -> Self {
        Arc::make_mut(&mut self.0).insert(o.schema, o);
        self
    }
    /// The adapter for a server that refused us naming schema `theirs`, if this client holds that version.
    pub fn for_refusal<A: Api>(&self, r: &Refusal) -> Option<ServerAdapter> {
        let theirs = match r {
            Refusal::Schema { ours, api, .. } | Refusal::SchemaAt { ours, api, .. } if api == A::NAME => *ours,
            _ => return None,
        };
        self.0.get(&theirs).map(|o| ServerAdapter::new::<A>(o.clone()))
    }
    /// The adapter for a wire-3 server that let us in and answered with op table `theirs`: none when every op of ours
    /// matches it (nothing to adapt) or the table is empty (a wire-2 server); else the older version whose table it is.
    pub fn for_table<A: Api>(&self, theirs: &[(u32, u64)]) -> Option<ServerAdapter> {
        if theirs.is_empty() {
            return None;
        }
        let mut t = theirs.to_vec();
        t.sort_unstable();
        let mut ours = crate::op_hashes::<A>();
        ours.sort_unstable();
        if t == ours {
            return None;
        }
        self.0.values().find(|o| o.table == t).map(|o| ServerAdapter::new::<A>(o.clone()))
    }
    /// The schema hashes of the older versions this client can call.
    pub fn schemas(&self) -> Vec<u64> {
        self.0.keys().copied().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The older versions a server of `A` answers, by schema hash.
#[derive(Clone, Default)]
pub struct Olders(pub(crate) Arc<HashMap<u64, Arc<Older>>>);

impl Olders {
    pub(crate) fn add(&mut self, o: Older) {
        Arc::make_mut(&mut self.0).insert(o.schema, Arc::new(o));
    }

    /// Schema hashes this server answers besides its own (for the door's REGISTER line and the Hello check).
    pub fn schemas(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.0.keys().copied().collect();
        v.sort();
        v
    }

    /// The adapter for a Hello's schema: None for the server's own schema (or one in `ACCEPTS`), Some for an older
    /// version it holds, Err for any other schema.
    pub fn for_hello<A: Api>(&self, schema: u64) -> Result<Option<Adapter>, ()> {
        if crate::schema_ok::<A>(schema) {
            return Ok(None);
        }
        self.0.get(&schema).map(|o| Some(Adapter { api: A::NAME, ours: A::VERSION, old: o.clone() })).ok_or(())
    }
}

/// ` accepts=<hex>,<hex>` for a REGISTER line: the older schemas this process answers (`ACCEPTS` and its adapters),
/// so the door hands it a caller built at one of them. Empty when there are none.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn accepts_field<A: Api>(o: &crate::adapt::Olders) -> String {
    let mut v: Vec<u64> = A::ACCEPTS.iter().copied().chain(o.schemas()).collect();
    v.sort();
    v.dedup();
    if v.is_empty() { return String::new() }
    format!(" accepts={}", v.iter().map(|h| format!("{h:016x}")).collect::<Vec<_>>().join(","))
}
