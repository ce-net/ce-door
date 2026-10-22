//! tokio client and server over one TCP connection per peer pair, requests multiplexed by `req_id`.
use crate::proto::*;
use crate::{Api, Header, Kind, Op, Stream, HEADER};
use std::sync::atomic::AtomicBool;
use serde::Serialize;
use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::{mpsc, oneshot};


pub(crate) async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R, buf: &mut Vec<u8>) -> Result<Header, WireError> {
    let mut hb = [0u8; HEADER];
    r.read_exact(&mut hb).await.map_err(|_| WireError::Closed)?;
    let h = Header::decode(&hb).map_err(|e| WireError::Decode(format!("{e:?}")))?;
    buf.resize(h.len as usize, 0);
    r.read_exact(buf).await.map_err(|_| WireError::Closed)?;
    Ok(h)
}

/// Writer task: drains the channel, flushes only when it is empty, so pipelined frames share one syscall.
/// Writes frames until every sender is dropped (returns the writer) or a write fails (`None`).
async fn writer<W: tokio::io::AsyncWrite + Unpin>(mut w: BufWriter<W>, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) -> Option<BufWriter<W>> {
    while let Some(f) = rx.recv().await {
        if w.write_all(&f).await.is_err() {
            return None;
        }
        while let Ok(f) = rx.try_recv() {
            if w.write_all(&f).await.is_err() {
                return None;
            }
        }
        if w.flush().await.is_err() {
            return None;
        }
    }
    Some(w)
}

fn tune(s: &TcpStream) {
    let _ = s.set_nodelay(true);
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<(Kind, Vec<u8>)>>>>;
type Subs = Arc<Mutex<HashMap<u64, mpsc::UnboundedSender<(Kind, Vec<u8>)>>>>;

/// A typed connection to one app. `call::<O>` compiles only for ops of API `A`.
pub struct Client<A: Api> {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    pending: Pending,
    subs: Subs,
    next: AtomicU64,
    pub deadline: Duration,
    session: u64,
    /// Set when the server is an older version this client holds adapters for ([`Client::connect_older`]).
    adapt: Option<crate::adapt::ServerAdapter>,
    _a: PhantomData<fn() -> A>,
}

impl<A: Api> Client<A> {
    /// This connection's datagram key, for [`DatagramSocket::send`].
    pub fn session(&self) -> u64 {
        self.session
    }

    pub async fn connect(addr: impl ToSocketAddrs, token: Vec<u8>) -> Result<Self, WireError> {
        Self::connect_opts(addr, token, false, DEADLINE).await
    }

    /// `spawn`: ask a door to start the cell if it is not running there; `wait`: how long to wait for the Hello answer.
    /// A door that answers `SchemaAt` with an update under way gets one retry that waits up to
    /// [`crate::DRIFT_WAIT`]: the door holds that Hello until the new build registers.
    pub async fn connect_opts(addr: impl ToSocketAddrs, token: Vec<u8>, spawn: bool, wait: Duration) -> Result<Self, WireError> {
        Self::connect_opts_as(addr, A::NAME, token, spawn, wait).await
    }

    /// [`Client::connect`] to instance `name` of the api (`<api>#<name>`, `ce_wire::instance_key`): a door hands the
    /// connection to that instance only. `token` must be signed for the instance name (`ce_gate::proof_as`).
    pub async fn connect_instance(addr: impl ToSocketAddrs, name: &str, token: Vec<u8>) -> Result<Self, WireError> {
        Self::connect_opts_as(addr, &crate::instance_key(A::NAME, name), token, false, DEADLINE).await
    }

    /// [`Client::connect_opts`] with the Hello naming `hello_api`: `A::NAME` or `<A::NAME>#<instance>`.
    pub async fn connect_opts_as(addr: impl ToSocketAddrs, hello_api: &str, token: Vec<u8>, spawn: bool, wait: Duration) -> Result<Self, WireError> {
        if !crate::hello_is::<A>(hello_api) {
            return Err(WireError::Io(format!("{hello_api} is not {} or an instance of it", A::NAME)));
        }
        let addrs: Vec<std::net::SocketAddr> = tokio::time::timeout(DEADLINE, tokio::net::lookup_host(addr)).await.map_err(|_| WireError::Timeout)?.map_err(io)?.collect();
        match Self::connect_hello(&addrs, hello_api, token.clone(), spawn, wait).await {
            Err(WireError::Refused(r)) if r.update_pending() => {
                eprintln!("ce-wire: {hello_api}: {r:?}; one retry, waiting up to {:?}", crate::DRIFT_WAIT);
                Self::connect_hello(&addrs, hello_api, token, spawn, crate::DRIFT_WAIT).await
            }
            r => r,
        }
    }

    /// Like [`Client::connect`], and a server at an older version this client holds adapters for (`ce-wire-gen adapt`
    /// writes `older_server()`) is called through them: each request goes down to its op, each answer comes up typed.
    /// The server is recognised by its Schema refusal (wire 2) or its op table (wire 3); the client then says Hello as
    /// that version. Ops the old server never had are refused before they are sent ([`crate::AdaptError::NoPath`]).
    pub async fn connect_older(addr: impl ToSocketAddrs, token: Vec<u8>, olders: crate::adapt::OlderServers) -> Result<Self, WireError> {
        Self::connect_older_opts(addr, token, &olders, DEADLINE).await
    }

    pub(crate) async fn connect_older_opts(addr: impl ToSocketAddrs, token: Vec<u8>, olders: &crate::adapt::OlderServers, wait: Duration) -> Result<Self, WireError> {
        let addrs: Vec<std::net::SocketAddr> = tokio::time::timeout(DEADLINE, tokio::net::lookup_host(addr)).await.map_err(|_| WireError::Timeout)?.map_err(io)?.collect();
        let a = match Self::connect_as(&addrs, A::NAME, token.clone(), false, wait, None).await {
            Ok((c, theirs)) => match olders.for_table::<A>(&theirs) {
                None => return Ok(c),
                Some(a) => a,
            },
            Err(WireError::Refused(r)) => match olders.for_refusal::<A>(&r) {
                None => return Err(WireError::Refused(r)),
                Some(a) => a,
            },
            Err(e) => return Err(e),
        };
        Self::connect_as(&addrs, A::NAME, token, false, wait, Some(a)).await.map(|(c, _)| c)
    }

    /// The server's version when this connection adapts to an older one; `None` when it is at ours.
    pub fn server_version(&self) -> Option<u32> {
        self.adapt.as_ref().map(|a| a.version())
    }

    async fn connect_hello(addrs: &[std::net::SocketAddr], hello_api: &str, token: Vec<u8>, spawn: bool, wait: Duration) -> Result<Self, WireError> {
        Self::connect_as(addrs, hello_api, token, spawn, wait, None).await.map(|(c, _)| c)
    }

    /// One Hello, as `A` or (with `adapt`) as the older version it names; also returns the server's op table.
    async fn connect_as(addrs: &[std::net::SocketAddr], hello_api: &str, token: Vec<u8>, spawn: bool, wait: Duration, adapt: Option<crate::adapt::ServerAdapter>) -> Result<(Self, Vec<(u32, u64)>), WireError> {
        let s = tokio::time::timeout(DEADLINE, TcpStream::connect(addrs)).await.map_err(|_| WireError::Timeout)?.map_err(io)?;
        tune(&s);
        let peer = s.peer_addr().ok();
        Self::hello_on(s, hello_api, token, spawn, wait, adapt, peer).await
    }

    /// [`Client::connect`] over a byte stream that is already open: a WebSocket bridged to bytes (wire-ws-client), a
    /// pipe, a TLS stream. The Hello never asks the far side to start a cell.
    pub async fn connect_stream<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static>(s: S, token: Vec<u8>) -> Result<Self, WireError> {
        Self::hello_on(s, A::NAME, token, false, DEADLINE, None, None).await.map(|(c, _)| c)
    }

    async fn hello_on<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static>(s: S, hello_api: &str, token: Vec<u8>, spawn: bool, wait: Duration, adapt: Option<crate::adapt::ServerAdapter>, peer: Option<std::net::SocketAddr>) -> Result<(Self, Vec<(u32, u64)>), WireError> {
        let (r, w) = tokio::io::split(s);
        let mut r = BufReader::new(r);
        let mut w = BufWriter::new(w);
        let (version, schema, table) = match &adapt {
            Some(a) => (a.version(), a.schema(), a.table().to_vec()),
            None => (A::VERSION, A::SCHEMA, crate::op_hashes::<A>()),
        };
        let hello = Hello { api: hello_api.into(), version, schema, token, spawn };
        let mut p = crate::hello_payload_ops(&hello, wait, &table).map_err(WireError::Decode)?;
        // provider proof: only when a verifier is installed; off = the same bytes as before
        let verify = crate::provider::verifier().map(|v| (v, crate::provider::new_ask()));
        if let Some((_, ask)) = &verify {
            crate::provider::append_ask(&mut p, ask);
        }
        w.write_all(&frame(Kind::Hello, 0, 0, &p)).await.map_err(io)?;
        w.flush().await.map_err(io)?;
        let mut buf = Vec::new();
        let h = tokio::time::timeout(wait, read_frame(&mut r, &mut buf)).await.map_err(|_| WireError::Timeout)??;
        let (ans, server_ops) = crate::split_answer(&buf).map_err(WireError::Decode)?;
        let session = match (h.kind, ans) {
            (Kind::Hello, Refusal::Ok { session }) => session,
            (_, ans) => return Err(WireError::Refused(ans)),
        };
        if let Some((v, ask)) = &verify {
            let ctx = crate::provider::Ctx { hello_api, schema, token: &hello.token, ask, peer };
            let proof = crate::provider::proof_in_answer(&buf);
            v(&ctx, proof.as_deref()).map_err(|e| WireError::Refused(Refusal::Gate(format!("provider: {e}"))))?;
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let pending: Pending = Arc::default();
        let subs: Subs = Arc::default();
        let (p2, s2) = (pending.clone(), subs.clone());
        let reader = tokio::spawn(async move {
            let mut buf = Vec::new();
            while let Ok(h) = read_frame(&mut r, &mut buf).await {
                let body = std::mem::take(&mut buf);
                if matches!(h.kind, Kind::Item | Kind::End) || (h.kind == Kind::Err && s2.lock().unwrap().contains_key(&h.req_id)) {
                    let mut subs = s2.lock().unwrap();
                    if let Some(s) = subs.get(&h.req_id) {
                        let _ = s.send((h.kind, body));
                    }
                    if h.kind != Kind::Item {
                        subs.remove(&h.req_id);
                    }
                } else if let Some(s) = p2.lock().unwrap().remove(&h.req_id) {
                    let _ = s.send((h.kind, body));
                }
            }
            p2.lock().unwrap().clear(); // drops every waiter: their calls return Closed
            s2.lock().unwrap().clear(); // ends every subscription with Closed
        });
        // The last Client or Subscription gone closes the socket: a relay (ce-node :7700) never answers a half-close,
        // so a reader left holding the read half kept one socket per dropped client.
        let reader = reader.abort_handle();
        tokio::spawn(async move {
            if let Some(mut w) = writer(w, rx).await {
                let _ = w.shutdown().await;
                reader.abort();
            }
        });
        Ok((Client { tx, pending, subs, next: AtomicU64::new(1), deadline: DEADLINE, session, adapt, _a: PhantomData }, server_ops))
    }

    /// Open a typed server-push stream. Items arrive in order on one TCP connection; dropping the
    /// [`Subscription`] stops the stream on the server.
    pub fn subscribe<S: Stream<Api = A>>(&self, req: &S::Req) -> Result<Subscription<S>, WireError> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let p = postcard::to_stdvec(req).map_err(|e| WireError::Decode(e.to_string()))?;
        let (op, p) = match &self.adapt {
            Some(a) => a.sub_out(S::ID, &p).map_err(WireError::Refused)?,
            None => (S::ID, p),
        };
        let (s, rx) = mpsc::unbounded_channel();
        self.subs.lock().unwrap().insert(id, s);
        self.tx.send(frame(Kind::Sub, id, op, &p)).map_err(|_| WireError::Closed)?;
        Ok(Subscription { rx, id, tx: self.tx.clone(), subs: self.subs.clone(), done: false, adapt: self.adapt.clone(), _s: PhantomData })
    }

    pub async fn call<O: Op<Api = A>>(&self, req: &O::Req) -> Result<O::Resp, WireError> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let p = postcard::to_stdvec(req).map_err(|e| WireError::Decode(e.to_string()))?;
        let (op, p) = match &self.adapt {
            Some(a) => a.req_out(O::ID, &p).map_err(WireError::Refused)?,
            None => (O::ID, p),
        };
        let (s, r) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, s);
        self.tx.send(frame(Kind::Req, id, op, &p)).map_err(|_| WireError::Closed)?;
        let got = tokio::time::timeout(crate::op_deadline::<O>(self.deadline), r).await;
        let (kind, body) = match got {
            Err(_) => {
                self.pending.lock().unwrap().remove(&id);
                return Err(WireError::Timeout);
            }
            Ok(Err(_)) => return Err(WireError::Closed),
            Ok(Ok(x)) => x,
        };
        match kind {
            Kind::Resp => {
                let body = match &self.adapt {
                    Some(a) => a.resp_in(O::ID, &body).map_err(WireError::Refused)?,
                    None => body,
                };
                postcard::from_bytes(&body).map_err(|e| WireError::Decode(e.to_string()))
            }
            _ => Err(WireError::Refused(postcard::from_bytes(&body).unwrap_or(Refusal::Remote("bad error body".into())))),
        }
    }
}

/// The names a process of `api` is registered under at the door `addr` (`10.0.1.2:7700`): the bare api and every
/// `<api>#<instance>`, sorted. Asks with a Hello for `<api>#*`; no token needed (the same names are in the DHT as
/// `wire:<api>#<instance>`). An older door answers NoCell.
pub async fn instances_at(addr: impl ToSocketAddrs, api: &str) -> Result<Vec<String>, WireError> {
    let addrs: Vec<std::net::SocketAddr> = tokio::time::timeout(DEADLINE, tokio::net::lookup_host(addr)).await.map_err(|_| WireError::Timeout)?.map_err(io)?.collect();
    let s = tokio::time::timeout(DEADLINE, TcpStream::connect(&addrs[..])).await.map_err(|_| WireError::Timeout)?.map_err(io)?;
    tune(&s);
    let (r, mut w) = tokio::io::split(s);
    let mut r = BufReader::new(r);
    let hello = Hello { api: format!("{}{}*", crate::base_api(api), crate::INSTANCE_SEP), version: 0, schema: 0, token: vec![], spawn: false };
    let p = crate::hello_payload_ops(&hello, DEADLINE, &[]).map_err(WireError::Decode)?;
    w.write_all(&frame(Kind::Hello, 0, 0, &p)).await.map_err(io)?;
    w.flush().await.map_err(io)?;
    let mut buf = Vec::new();
    tokio::time::timeout(DEADLINE, read_frame(&mut r, &mut buf)).await.map_err(|_| WireError::Timeout)??;
    match crate::split_answer(&buf).map_err(WireError::Decode)?.0 {
        Refusal::Instances(v) => Ok(v),
        other => Err(WireError::Refused(other)),
    }
}

/// The client end of a [`Stream`]: `while let Some(item) = sub.next().await { let state = item?; .. }`.
pub struct Subscription<S: Stream> {
    rx: mpsc::UnboundedReceiver<(Kind, Vec<u8>)>,
    id: u64,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    subs: Subs,
    done: bool,
    adapt: Option<crate::adapt::ServerAdapter>,
    _s: PhantomData<fn() -> S>,
}

impl<S: Stream> Subscription<S> {
    /// Next item; `None` when the server ended the stream normally.
    pub async fn next(&mut self) -> Option<Result<S::Item, WireError>> {
        if self.done {
            return None;
        }
        let Some((kind, body)) = self.rx.recv().await else {
            self.done = true;
            return Some(Err(WireError::Closed));
        };
        match kind {
            Kind::Item => {
                let body = match self.adapt.as_ref().map(|a| a.item_in(S::ID, &body)) {
                    None => body,
                    Some(Ok(b)) => b,
                    // an item this version cannot carry ends the stream with the typed reason (dropping cancels it)
                    Some(Err(r)) => {
                        self.done = true;
                        return Some(Err(WireError::Refused(r)));
                    }
                };
                Some(postcard::from_bytes(&body).map_err(|e| WireError::Decode(e.to_string())))
            }
            Kind::End => {
                self.done = true;
                None
            }
            _ => {
                self.done = true;
                Some(Err(WireError::Refused(postcard::from_bytes(&body).unwrap_or(Refusal::Remote("bad error body".into())))))
            }
        }
    }

    /// Newest item already received, skipping older ones (latest wins); waits if none is queued.
    pub async fn latest(&mut self) -> Option<Result<S::Item, WireError>> {
        let mut last = self.next().await?;
        while let Ok((kind, body)) = self.rx.try_recv() {
            match kind {
                Kind::Item => last = postcard::from_bytes(&body).map_err(|e| WireError::Decode(e.to_string())),
                _ => {
                    self.done = true;
                    break;
                }
            }
        }
        Some(last)
    }
}

impl<S: Stream> Drop for Subscription<S> {
    fn drop(&mut self) {
        if self.subs.lock().unwrap().remove(&self.id).is_some() {
            let _ = self.tx.send(frame(Kind::End, self.id, S::ID, &[]));
        }
    }
}

/// The server end of one open stream. `send` fails once the client has gone or cancelled: end the handler then.
pub struct Sink<I> {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    id: u64,
    op: u32,
    cancelled: Arc<AtomicBool>,
    _i: PhantomData<fn(I)>,
}

impl<I: Serialize> Sink<I> {
    pub fn send(&self, item: &I) -> Result<(), WireError> {
        if !self.is_open() {
            return Err(WireError::Closed);
        }
        let p = postcard::to_stdvec(item).map_err(|e| WireError::Decode(e.to_string()))?;
        self.tx.send(frame(Kind::Item, self.id, self.op, &p)).map_err(|_| WireError::Closed)
    }

    pub fn is_open(&self) -> bool {
        !self.cancelled.load(Ordering::Relaxed) && !self.tx.is_closed()
    }
}

type BoxFut = Pin<Box<dyn Future<Output = Result<Vec<u8>, Refusal>> + Send>>;
type Handler = Arc<dyn Fn(Vec<u8>, Caller) -> BoxFut + Send + Sync>;
type StreamFut = Pin<Box<dyn Future<Output = Result<(), Refusal>> + Send>>;
type StreamHandler = Arc<dyn Fn(Vec<u8>, Caller, mpsc::UnboundedSender<Vec<u8>>, u64, Arc<AtomicBool>) -> StreamFut + Send + Sync>;
type Gate = Arc<dyn Fn(&Hello) -> Result<Caller, String> + Send + Sync>;
/// A cell's dying routine (`Server::on_apoptosis`, src/apoptosis.rs).
pub(crate) type ApoHook = Arc<dyn Fn(crate::ApoptosisReq) -> Pin<Box<dyn Future<Output = Result<crate::Saved, String>> + Send>> + Send + Sync>;

/// A typed server for API `A`. Every op declares the right it needs; the server checks it before the handler runs.
pub struct Server<A: Api> {
    ops: HashMap<u32, Handler>,
    streams: HashMap<u32, StreamHandler>,
    gate: Gate,
    sessions: Sessions,
    audit: Option<Audit>,
    names: HashMap<u32, (&'static str, &'static str)>,
    olders: crate::adapt::Olders,
    apoptosis: Option<(u32, ApoHook)>,
    _a: PhantomData<fn() -> A>,
}

/// The audit observer (ce_gate::audit::file writes the hash-chained per-node file).
pub type Audit = Arc<dyn Fn(&CallRecord) + Send + Sync>;

impl<A: Api> Server<A> {
    /// `gate` turns a Hello token into a Caller or refuses it. ce-gate provides the ce-cap one.
    pub fn new(gate: impl Fn(&Hello) -> Result<Caller, String> + Send + Sync + 'static) -> Self {
        Server { ops: HashMap::new(), streams: HashMap::new(), gate: Arc::new(gate), sessions: Arc::default(), audit: None, names: HashMap::new(), olders: Default::default(), apoptosis: None, _a: PhantomData }
    }

    /// Also answer callers built at an older version of `A`, through the typed adapters in `o`
    /// (src/adapt.rs; `ce-wire-gen adapt` writes them). Call once per older version.
    pub fn older(mut self, o: crate::adapt::Older) -> Self {
        self.olders.add(o);
        self
    }

    /// The cell's dying routine: the door calls it before it stops the process (idle, stop, restart, update), and
    /// SIGTERM runs it too; `f` saves what must survive (state.store, a file) and says what it saved. It gets
    /// [`crate::APOPTOSIS_MS`]; [`Self::on_apoptosis_within`] asks for more. Without one the cell answers
    /// `Saved::default()` at once.
    pub fn on_apoptosis<F, Fut>(self, f: F) -> Self
    where
        F: Fn(crate::ApoptosisReq) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<crate::Saved, String>> + Send + 'static,
    {
        self.on_apoptosis_within(crate::APOPTOSIS_MS, f)
    }

    /// [`Self::on_apoptosis`] with `ms` for the routine (at most [`crate::APOPTOSIS_MAX_MS`]).
    pub fn on_apoptosis_within<F, Fut>(mut self, ms: u32, f: F) -> Self
    where
        F: Fn(crate::ApoptosisReq) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<crate::Saved, String>> + Send + 'static,
    {
        let f = Arc::new(f);
        let h: ApoHook = Arc::new(move |r| {
            let f = f.clone();
            Box::pin(async move { f(r).await })
        });
        self.apoptosis = Some((ms.clamp(1, crate::APOPTOSIS_MAX_MS), h));
        self
    }

    /// Call `f` once per answered op request (refused ones too), after the reply is sent.
    pub fn audit(mut self, f: impl Fn(&CallRecord) + Send + Sync + 'static) -> Self {
        self.audit = Some(Arc::new(f));
        self
    }

    pub fn on<O, F, Fut>(mut self, f: F) -> Self
    where
        O: Op<Api = A>,
        F: Fn(O::Req, Caller) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<O::Resp, String>> + Send + 'static,
    {
        let f = Arc::new(f);
        let h: Handler = Arc::new(move |body: Vec<u8>, who: Caller| {
            let f = f.clone();
            Box::pin(async move {
                if !who.has(O::RIGHT) {
                    return Err(Refusal::Right(O::RIGHT.into()));
                }
                let req: O::Req = postcard::from_bytes(&body).map_err(|e| Refusal::Decode(e.to_string()))?;
                let resp = f(req, who).await.map_err(Refusal::Remote)?;
                postcard::to_stdvec(&resp).map_err(|e| Refusal::Decode(e.to_string()))
            }) as BoxFut
        });
        self.ops.insert(O::ID, h);
        self.names.insert(O::ID, (O::NAME, O::RIGHT));
        self
    }

    /// Serve stream `S`: the handler gets the request, the caller and a [`Sink`]; it sends items until it returns
    /// or `send` fails. Returning `Ok` ends the stream normally, `Err` ends it with a typed error.
    pub fn stream<S, F, Fut>(mut self, f: F) -> Self
    where
        S: Stream<Api = A>,
        F: Fn(S::Req, Caller, Sink<S::Item>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let f = Arc::new(f);
        let h: StreamHandler = Arc::new(move |body, who: Caller, tx, id, cancelled| {
            let f = f.clone();
            Box::pin(async move {
                if !who.has(S::RIGHT) {
                    return Err(Refusal::Right(S::RIGHT.into()));
                }
                let req: S::Req = postcard::from_bytes(&body).map_err(|e| Refusal::Decode(e.to_string()))?;
                f(req, who, Sink { tx, id, op: S::ID, cancelled, _i: PhantomData }).await.map_err(Refusal::Remote)
            }) as StreamFut
        });
        self.streams.insert(S::ID, h);
        self
    }

    /// The gated callers of this server, for a [`DatagramSocket`].
    pub fn sessions(&self) -> Sessions {
        self.sessions.clone()
    }

    /// Serve until the listener fails. Bind it to 127.0.0.1 and the node's nm0 address, never 0.0.0.0.
    pub async fn serve(self, l: TcpListener) -> std::io::Result<()> {
        let inner = self.into_inner();
        #[cfg(all(feature = "server", unix))]
        crate::door::sigterm_routine(&inner);
        let mut bad = 0u32;
        loop {
            // EMFILE/ENFILE (out of fds) or a connection reset before accept loses that one caller, never the
            // cell; a long run of failures still ends it
            let s = match l.accept().await {
                Ok((s, _)) => {
                    bad = 0;
                    s
                }
                Err(e) if bad < 100 => {
                    bad += 1;
                    eprintln!("ce-wire {}: accept failed: {e}", A::NAME);
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    continue;
                }
                Err(e) => return Err(e),
            };
            inner.clone().spawn_conn(s, None);
        }
    }

    pub(crate) fn into_inner(self) -> Arc<Inner<A>> {
        Arc::new(Inner {
            ops: Arc::new(self.ops),
            streams: Arc::new(self.streams),
            gate: self.gate,
            sessions: self.sessions,
            audit: self.audit.map(|f| (f, Arc::new(self.names))),
            olders: self.olders,
            apoptosis: self.apoptosis,
            _a: PhantomData,
        })
    }
}

type AuditWith = (Audit, Arc<HashMap<u32, (&'static str, &'static str)>>);

pub(crate) struct Inner<A: Api> {
    ops: Arc<HashMap<u32, Handler>>,
    streams: Arc<HashMap<u32, StreamHandler>>,
    gate: Gate,
    sessions: Sessions,
    audit: Option<AuditWith>,
    pub(crate) olders: crate::adapt::Olders,
    pub(crate) apoptosis: Option<(u32, ApoHook)>,
    _a: PhantomData<fn() -> A>,
}

impl<A: Api> Inner<A> {
    /// Run one connection. `hello`: the Hello frame (header + payload) when a door already read it off the socket.
    pub(crate) fn spawn_conn(self: Arc<Self>, s: TcpStream, hello: Option<Vec<u8>>) {
        tune(&s);
        let key = session_key();
        tokio::spawn(async move {
            let (ops, streams, gate, sessions) = (self.ops.clone(), self.streams.clone(), self.gate.clone(), self.sessions.clone());
            let _ = conn::<A>(s, hello, ops, streams, gate, sessions.clone(), key, self.audit.clone(), self.olders.clone()).await;
            sessions.lock().unwrap().remove(&key);
        });
    }
}

async fn conn<A: Api>(
    s: TcpStream,
    hello: Option<Vec<u8>>,
    ops: Arc<HashMap<u32, Handler>>,
    streams: Arc<HashMap<u32, StreamHandler>>,
    gate: Gate,
    sessions: Sessions,
    key: u64,
    audit: Option<AuditWith>,
    olders: crate::adapt::Olders,
) -> Result<(), WireError> {
    let (r, w) = s.into_split();
    let mut r = BufReader::new(r);
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(writer(BufWriter::new(w), rx));
    let mut buf = Vec::new();
    let h = match hello {
        Some(f) => {
            let mut c = std::io::Cursor::new(f);
            read_frame(&mut c, &mut buf).await?
        }
        None => tokio::time::timeout(DEADLINE, read_frame(&mut r, &mut buf)).await.map_err(|_| WireError::Timeout)??,
    };
    let mut adapter = None;
    // a wire-3 caller whose whole schema differs and that no adapter covers is let in op by op: each call is checked
    // against its per-op hash
    let mut per_op: Option<(HashMap<u32, u64>, HashMap<u32, u64>)> = None;
    let mut wire = 1;
    let ans = if h.kind != Kind::Hello {
        Err(Refusal::Decode("first frame must be Hello".into()))
    } else {
        match crate::split_hello_ops(&buf) {
            Err(e) => Err(Refusal::Decode(e)),
            Ok((hello, ext, peer)) => {
                wire = ext.wire;
                match crate::hello_is::<A>(&hello.api).then(|| olders.for_hello::<A>(hello.schema)) {
                    Some(Ok(a)) => {
                        adapter = a;
                        gate(&hello).map_err(Refusal::Gate)
                    }
                    Some(Err(())) if { per_op = crate::per_op_admit::<A>(peer); per_op.is_some() } => {
                        gate(&hello).map_err(Refusal::Gate)
                    }
                    _ => Err(Refusal::Schema { ours: A::SCHEMA, theirs: hello.schema, api: A::NAME.into() }),
                }
            }
        }
    };
    let who = match ans {
        Ok(who) => {
            sessions.lock().unwrap().insert(key, who.clone());
            let _ = tx.send(frame(Kind::Hello, 0, 0, &crate::provider::ok_answer_for::<A>(&buf, key, wire)));
            who
        }
        Err(e) => {
            let _ = tx.send(frame(Kind::Hello, 0, 0, &postcard::to_stdvec(&e).unwrap()));
            return Ok(());
        }
    };
    let open: Arc<Mutex<HashMap<u64, Arc<AtomicBool>>>> = Arc::default();
    loop {
        let h = read_frame(&mut r, &mut buf).await?;
        match h.kind {
            Kind::End => {
                if let Some(c) = open.lock().unwrap().remove(&h.req_id) {
                    c.store(true, Ordering::Relaxed);
                }
                continue;
            }
            Kind::Sub => {
                let tx = tx.clone();
                if let Some(e) = per_op.as_ref().and_then(|(p, o)| crate::per_op_check::<A>(p, o, h.op)) {
                    let _ = tx.send(frame(Kind::Err, h.req_id, h.op, &postcard::to_stdvec(&e).unwrap()));
                    continue;
                }
                // an older caller: its stream id and request become the current ones, and every item goes back down
                let (cur, body_in) = match &adapter {
                    None => (h.op, None),
                    Some(a) => match a.sub_in(h.op, &buf) {
                        Ok((op, b)) => (op, Some(b)),
                        Err(e) => {
                            let _ = tx.send(frame(Kind::Err, h.req_id, h.op, &postcard::to_stdvec(&e).unwrap()));
                            continue;
                        }
                    },
                };
                let Some(st) = streams.get(&cur).cloned() else {
                    let _ = tx.send(frame(Kind::Err, h.req_id, h.op, &postcard::to_stdvec(&Refusal::UnknownOp(h.op)).unwrap()));
                    continue;
                };
                let cancelled = Arc::new(AtomicBool::new(false));
                open.lock().unwrap().insert(h.req_id, cancelled.clone());
                let body = match body_in { Some(b) => b, None => std::mem::take(&mut buf) };
                let (who, open) = (who.clone(), open.clone());
                let items = match &adapter {
                    None => tx.clone(),
                    Some(a) => item_down(a.clone(), tx.clone(), h.op, cancelled.clone()),
                };
                tokio::spawn(async move {
                    let r = st(body, who, items.clone(), h.req_id, cancelled.clone()).await;
                    open.lock().unwrap().remove(&h.req_id);
                    if !cancelled.load(Ordering::Relaxed) {
                        let f = match r {
                            Ok(()) => frame(Kind::End, h.req_id, h.op, &[]),
                            Err(e) => frame(Kind::Err, h.req_id, h.op, &postcard::to_stdvec(&e).unwrap()),
                        };
                        // the same channel as the items, so End never overtakes an item still being converted
                        let _ = items.send(f);
                    }
                });
                continue;
            }
            Kind::Req => {}
            _ => continue,
        }
        let tx = tx.clone();
        if let Some(e) = per_op.as_ref().and_then(|(p, o)| crate::per_op_check::<A>(p, o, h.op)) {
            let _ = tx.send(frame(Kind::Err, h.req_id, h.op, &postcard::to_stdvec(&e).unwrap()));
            continue;
        }
        // an older caller: its op id and body become the current ones before dispatch (src/adapt.rs)
        let (cur, body_in) = match &adapter {
            None => (h.op, None),
            Some(a) => match a.req_in(h.op, &buf) {
                Ok((op, b)) => (op, Some(b)),
                Err(e) => {
                    let _ = tx.send(frame(Kind::Err, h.req_id, h.op, &postcard::to_stdvec(&e).unwrap()));
                    continue;
                }
            },
        };
        let Some(op) = ops.get(&cur).cloned() else {
            let _ = tx.send(frame(Kind::Err, h.req_id, h.op, &postcard::to_stdvec(&Refusal::UnknownOp(h.op)).unwrap()));
            continue;
        };
        let body = match body_in { Some(b) => b, None => std::mem::take(&mut buf) };
        let (who, audit, adapter) = (who.clone(), audit.clone(), adapter.clone());
        tokio::spawn(async move {
            let t0 = std::time::Instant::now();
            let caller = audit.as_ref().map(|_| (who.name.clone(), who.rights.iter().find_map(|r| r.strip_prefix(GRANT_RIGHT)).unwrap_or("").to_string()));
            let r = op(body, who).await;
            let r = match (r, &adapter) {
                (Ok(p), Some(a)) => a.resp_out(h.op, &p),
                (r, _) => r,
            };
            let us = t0.elapsed().as_micros() as u64;
            let refusal = r.as_ref().err().map(|e| format!("{e:?}"));
            let f = match r {
                Ok(p) => frame(Kind::Resp, h.req_id, h.op, &p),
                Err(e) => frame(Kind::Err, h.req_id, h.op, &postcard::to_stdvec(&e).unwrap()),
            };
            let _ = tx.send(f);
            if let (Some((f, names)), Some((caller, grant))) = (audit, caller) {
                let (op_name, right) = names.get(&cur).copied().unwrap_or(("?", "?"));
                f(&CallRecord { api: A::NAME, op: h.op, op_name, right, caller, grant, ok: refusal.is_none(), refusal: refusal.unwrap_or_default(), us });
            }
        });
    }
}

/// The sender a stream handler writes to when its caller is an older version: each Item frame is converted down
/// (`old_op`: the caller's stream id) before it reaches the socket. An item that cannot be carried ends the stream with
/// its typed refusal and cancels the handler; End and Err frames pass through.
fn item_down(a: crate::adapt::Adapter, tx: mpsc::UnboundedSender<Vec<u8>>, old_op: u32, cancelled: Arc<AtomicBool>) -> mpsc::UnboundedSender<Vec<u8>> {
    let (itx, mut irx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Some(f) = irx.recv().await {
            let Some(h) = f.get(..HEADER).and_then(|b| <&[u8; HEADER]>::try_from(b).ok()).and_then(|b| Header::decode(b).ok()) else { continue };
            if h.kind != Kind::Item {
                let _ = tx.send(f);
                continue;
            }
            match a.item_out(old_op, &f[HEADER..]) {
                Ok(b) => {
                    let _ = tx.send(frame(Kind::Item, h.req_id, old_op, &b));
                }
                Err(e) => {
                    cancelled.store(true, Ordering::Relaxed);
                    let _ = tx.send(frame(Kind::Err, h.req_id, old_op, &postcard::to_stdvec(&e).unwrap()));
                    break;
                }
            }
        }
    });
    itx
}

/// Typed UDP datagrams for real-time streams (servo goals, telemetry): no retry, no queue, stale ones dropped.
/// The u64 seq rides in the header's req_id; the payload starts with the sender's 8-byte session key. A receiver keeps the newest seq per (sender, op) and drops anything
/// older or equal, so a burst that arrives late over the net.mesh leg never replays old goals.
pub struct DatagramSocket<A: Api> {
    sock: tokio::net::UdpSocket,
    seq: AtomicU64,
    last: HashMap<(std::net::SocketAddr, u32), u64>,
    sessions: Option<Sessions>,
    buf: Vec<u8>,
    _a: PhantomData<fn() -> A>,
}

/// One received datagram, decoded only as the op it claims to be.
pub struct Datagram {
    pub from: std::net::SocketAddr,
    pub op: u32,
    pub seq: u64,
    pub caller: Option<Caller>,
    body: Vec<u8>,
}

impl Datagram {
    pub fn decode<O: Op>(&self) -> Option<O::Req> {
        if self.op != O::ID {
            return None;
        }
        postcard::from_bytes(&self.body).ok()
    }
}

impl<A: Api> DatagramSocket<A> {
    /// `sessions`: the receiving server's gated callers; `None` for a send-only socket.
    pub async fn bind(addr: impl ToSocketAddrs, sessions: Option<Sessions>) -> std::io::Result<Self> {
        let sock = tokio::net::UdpSocket::bind(addr).await?;
        Ok(DatagramSocket { sock, seq: AtomicU64::new(1), last: HashMap::new(), sessions, buf: vec![0; 2048], _a: PhantomData })
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.sock.local_addr()
    }

    /// `session`: [`Client::session`] of the sender's gated connection to the receiving server.
    pub async fn send<O: Op<Api = A>>(&self, to: std::net::SocketAddr, session: u64, msg: &O::Req) -> Result<u64, WireError> {
        let mut p = session.to_le_bytes().to_vec();
        p.extend(postcard::to_stdvec(msg).map_err(|e| WireError::Decode(e.to_string()))?);
        if p.len() > crate::MAX_DATAGRAM {
            return Err(WireError::Decode(format!("datagram {} B > {} B (nm0 MTU 1280)", p.len(), crate::MAX_DATAGRAM)));
        }
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        self.sock.send_to(&frame(Kind::Datagram, seq, O::ID, &p), to).await.map_err(io)?;
        Ok(seq)
    }

    /// Next fresh datagram from a gated caller that holds the op's right; everything else is dropped silently.
    pub async fn recv(&mut self, rights: &HashMap<u32, &'static str>) -> Result<Datagram, WireError> {
        loop {
            let (n, from) = self.sock.recv_from(&mut self.buf).await.map_err(io)?;
            if n < HEADER {
                continue;
            }
            let Ok(h) = Header::decode(self.buf[..HEADER].try_into().unwrap()) else { continue };
            if h.kind != Kind::Datagram || HEADER + h.len as usize != n || h.len < 8 {
                continue;
            }
            let key = u64::from_le_bytes(self.buf[HEADER..HEADER + 8].try_into().unwrap());
            let caller = match &self.sessions {
                Some(s) => match s.lock().unwrap().get(&key) {
                    Some(c) => Some(c.clone()),
                    None => continue,
                },
                None => None,
            };
            if let (Some(c), Some(right)) = (&caller, rights.get(&h.op)) {
                if !c.has(right) {
                    continue;
                }
            }
            let last = self.last.entry((from, h.op)).or_insert(0);
            if h.req_id <= *last {
                continue;
            }
            *last = h.req_id;
            return Ok(Datagram { from, op: h.op, seq: h.req_id, caller, body: self.buf[HEADER + 8..n].to_vec() });
        }
    }
}
