//! ce-wire on std threads, no async runtime (feature `blocking`, deps serde + postcard only). For thread-based
//! daemons like servo-bus-control. Same wire as the tokio side, so a tokio client talks to a blocking server and back:
//! same frames, Hello and Refusal, schema check, gate, per-op rights, session keys, datagram stale-drop, streams.
//!
//! Server threading: one thread per connection; requests on a connection run inline, in order, on that thread (a
//! slow op delays only its own connection). Each open stream gets its own thread. Writes from the connection thread
//! and stream threads share one mutex; a frame is written with one `write_all`.
use crate::proto::*;
use crate::{Api, Header, Kind, Op, Stream, HEADER};
use std::collections::HashMap;
use std::io::{BufReader, Read, Write};
use std::marker::PhantomData;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

fn read_frame(r: &mut impl Read, buf: &mut Vec<u8>) -> Result<Header, WireError> {
    let mut hb = [0u8; HEADER];
    r.read_exact(&mut hb).map_err(read_err)?;
    let h = Header::decode(&hb).map_err(|e| WireError::Decode(format!("{e:?}")))?;
    buf.resize(h.len as usize, 0);
    r.read_exact(buf).map_err(read_err)?;
    Ok(h)
}

fn read_err(e: std::io::Error) -> WireError {
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => WireError::Timeout,
        _ => WireError::Closed,
    }
}

fn enc<T: serde::Serialize>(v: &T) -> Vec<u8> {
    postcard::to_stdvec(v).unwrap_or_default()
}

type Out = Arc<Mutex<TcpStream>>;

fn send(w: &Out, f: &[u8]) -> Result<(), WireError> {
    w.lock().unwrap().write_all(f).map_err(|_| WireError::Closed)
}

type Handler = Arc<dyn Fn(&[u8], &Caller) -> Result<Vec<u8>, Refusal> + Send + Sync>;
type StreamHandler = Arc<dyn Fn(&[u8], Caller, Out, u64, Arc<AtomicBool>, Option<Down>) -> Result<(), Refusal> + Send + Sync>;
/// An older caller's stream: (its stream id, the adapter that carries each item down to it).
type Down = (u32, crate::adapt::Adapter);
type Gate = Arc<dyn Fn(&Hello) -> Result<Caller, String> + Send + Sync>;
type AuditFn = Arc<dyn Fn(&CallRecord) + Send + Sync>;

/// A typed blocking server for API `A`. Every op declares its right; the server checks it before the handler runs.
pub struct Server<A: Api> {
    ops: HashMap<u32, Handler>,
    streams: HashMap<u32, StreamHandler>,
    gate: Gate,
    sessions: Sessions,
    audit: Option<AuditFn>,
    names: HashMap<u32, (&'static str, &'static str)>,
    olders: crate::adapt::Olders,
    /// The dying routine and the time it gets (`on_apoptosis`).
    #[cfg_attr(not(feature = "blocking-door"), allow(dead_code))]
    apoptosis: Option<(u32, BlockingApoHook)>,
    _a: PhantomData<fn() -> A>,
}

/// A std-thread cell's dying routine (src/apoptosis.rs).
type BlockingApoHook = Arc<dyn Fn(crate::ApoptosisReq) -> Result<crate::Saved, String> + Send + Sync>;

impl<A: Api> Server<A> {
    pub fn new(gate: impl Fn(&Hello) -> Result<Caller, String> + Send + Sync + 'static) -> Self {
        Server { ops: HashMap::new(), streams: HashMap::new(), gate: Arc::new(gate), sessions: Arc::default(), audit: None, names: HashMap::new(), olders: Default::default(), apoptosis: None, _a: PhantomData }
    }

    /// The cell's dying routine (the tokio server's `on_apoptosis`): the door calls it before it stops the process;
    /// `f` saves what must survive and says what it saved, within [`crate::APOPTOSIS_MS`] (or `ms`, with
    /// [`Self::on_apoptosis_within`]). Without one the cell answers `Saved::default()`. SIGTERM does not run it here
    /// (a std-thread cell has no signal thread); the door asks before every stop it makes.
    pub fn on_apoptosis(self, f: impl Fn(crate::ApoptosisReq) -> Result<crate::Saved, String> + Send + Sync + 'static) -> Self {
        self.on_apoptosis_within(crate::APOPTOSIS_MS, f)
    }

    /// [`Self::on_apoptosis`] with `ms` for the routine (at most [`crate::APOPTOSIS_MAX_MS`]).
    pub fn on_apoptosis_within(mut self, ms: u32, f: impl Fn(crate::ApoptosisReq) -> Result<crate::Saved, String> + Send + Sync + 'static) -> Self {
        self.apoptosis = Some((ms.clamp(1, crate::APOPTOSIS_MAX_MS), Arc::new(f)));
        self
    }

    /// Also answer callers built at an older version of `A`, through typed adapters (the tokio server's `older`).
    pub fn older(mut self, o: crate::adapt::Older) -> Self {
        self.olders.add(o);
        self
    }

    /// Call `f` once per answered op request, refused or not, after the reply is sent (the tokio server's `audit`;
    /// `ce_gate::audit::file()` writes the per-node hash chain). Streams are not recorded.
    pub fn audit(mut self, f: impl Fn(&CallRecord) + Send + Sync + 'static) -> Self {
        self.audit = Some(Arc::new(f));
        self
    }

    pub fn on<O, F>(mut self, f: F) -> Self
    where
        O: Op<Api = A>,
        F: Fn(O::Req, &Caller) -> Result<O::Resp, String> + Send + Sync + 'static,
    {
        self.names.insert(O::ID, (O::NAME, O::RIGHT));
        self.ops.insert(
            O::ID,
            Arc::new(move |body: &[u8], who: &Caller| {
                if !who.has(O::RIGHT) {
                    return Err(Refusal::Right(O::RIGHT.into()));
                }
                let req: O::Req = postcard::from_bytes(body).map_err(|e| Refusal::Decode(e.to_string()))?;
                let resp = f(req, who).map_err(Refusal::Remote)?;
                postcard::to_stdvec(&resp).map_err(|e| Refusal::Decode(e.to_string()))
            }),
        );
        self
    }

    /// Serve stream `S` on its own thread: send items into the [`Sink`] until it returns or `send` fails.
    pub fn stream<S, F>(mut self, f: F) -> Self
    where
        S: Stream<Api = A>,
        F: Fn(S::Req, Caller, Sink<S::Item>) -> Result<(), String> + Send + Sync + 'static,
    {
        self.streams.insert(
            S::ID,
            Arc::new(move |body: &[u8], who: Caller, w: Out, id: u64, cancelled: Arc<AtomicBool>, down: Option<Down>| {
                if !who.has(S::RIGHT) {
                    return Err(Refusal::Right(S::RIGHT.into()));
                }
                let req: S::Req = postcard::from_bytes(body).map_err(|e| Refusal::Decode(e.to_string()))?;
                f(req, who, Sink { w, id, op: S::ID, cancelled, down, _i: PhantomData }).map_err(Refusal::Remote)
            }),
        );
        self
    }

    /// The gated callers of this server, for a [`DatagramSocket`].
    pub fn sessions(&self) -> Sessions {
        self.sessions.clone()
    }

    /// Accept forever, one thread per connection. Bind 127.0.0.1 and the node's nm0 address, never 0.0.0.0.
    pub fn serve(self, l: TcpListener) -> std::io::Result<()> {
        let s = Arc::new(self);
        loop {
            let (c, _) = l.accept()?;
            let s = s.clone();
            std::thread::spawn(move || s.serve_conn(c, None));
        }
    }

    /// Run one connection on this thread. `hello`: the Hello frame when a door already read it off the socket.
    pub fn serve_conn(&self, s: TcpStream, hello: Option<Vec<u8>>) {
        let key = session_key();
        let _ = self.conn(s, hello, key);
        self.sessions.lock().unwrap().remove(&key);
    }

    fn conn(&self, s: TcpStream, hello: Option<Vec<u8>>, key: u64) -> Result<(), WireError> {
        let _ = s.set_nodelay(true);
        let w: Out = Arc::new(Mutex::new(s.try_clone().map_err(io)?));
        let mut r = BufReader::new(s);
        let mut buf = Vec::new();
        let h = match hello {
            Some(f) => read_frame(&mut std::io::Cursor::new(f), &mut buf)?,
            None => {
                r.get_ref().set_read_timeout(Some(DEADLINE)).map_err(io)?;
                let h = read_frame(&mut r, &mut buf)?;
                r.get_ref().set_read_timeout(None).map_err(io)?;
                h
            }
        };
        let mut adapter = None;
        // a wire-3 caller let in op by op, like the tokio server
        let mut per_op: Option<(HashMap<u32, u64>, HashMap<u32, u64>)> = None;
        let mut wire = 1;
        let ans = if h.kind != Kind::Hello {
            Err(Refusal::Decode("first frame must be Hello".into()))
        } else {
            match crate::split_hello_ops(&buf) {
                Err(e) => Err(Refusal::Decode(e)),
                Ok((hello, ext, peer)) => {
                    wire = ext.wire;
                    match crate::hello_is::<A>(&hello.api).then(|| self.olders.for_hello::<A>(hello.schema)) {
                        Some(Ok(a)) => {
                            adapter = a;
                            (self.gate)(&hello).map_err(Refusal::Gate)
                        }
                        Some(Err(())) if { per_op = crate::per_op_admit::<A>(peer); per_op.is_some() } => {
                            (self.gate)(&hello).map_err(Refusal::Gate)
                        }
                        _ => Err(Refusal::Schema { ours: A::SCHEMA, theirs: hello.schema, api: A::NAME.into() }),
                    }
                }
            }
        };
        let who = match ans {
            Ok(who) => {
                self.sessions.lock().unwrap().insert(key, who.clone());
                send(&w, &frame(Kind::Hello, 0, 0, &crate::provider::ok_answer_for::<A>(&buf, key, wire)))?;
                who
            }
            Err(e) => return send(&w, &frame(Kind::Hello, 0, 0, &enc(&e))),
        };
        let open: Arc<Mutex<HashMap<u64, Arc<AtomicBool>>>> = Arc::default();
        let close_all = |open: &Mutex<HashMap<u64, Arc<AtomicBool>>>| {
            for (_, c) in open.lock().unwrap().drain() {
                c.store(true, Ordering::Relaxed);
            }
        };
        loop {
            let h = match read_frame(&mut r, &mut buf) {
                Ok(h) => h,
                Err(e) => {
                    close_all(&open);
                    return Err(e);
                }
            };
            if matches!(h.kind, Kind::Req | Kind::Sub) {
                if let Some(e) = per_op.as_ref().and_then(|(p, o)| crate::per_op_check::<A>(p, o, h.op)) {
                    send(&w, &frame(Kind::Err, h.req_id, h.op, &enc(&e)))?;
                    continue;
                }
            }
            match h.kind {
                Kind::Req => {
                    // an older caller: its op id and body become the current ones before dispatch (src/adapt.rs)
                    let (cur, body) = match &adapter {
                        None => (h.op, None),
                        Some(a) => match a.req_in(h.op, &buf) {
                            Ok((op, b)) => (op, Some(b)),
                            Err(e) => {
                                send(&w, &frame(Kind::Err, h.req_id, h.op, &enc(&e)))?;
                                continue;
                            }
                        },
                    };
                    let Some(op) = self.ops.get(&cur) else {
                        send(&w, &frame(Kind::Err, h.req_id, h.op, &enc(&Refusal::UnknownOp(h.op))))?;
                        continue;
                    };
                    let t0 = std::time::Instant::now();
                    let r = op(body.as_deref().unwrap_or(&buf), &who);
                    let r = match (r, &adapter) {
                        (Ok(p), Some(a)) => a.resp_out(h.op, &p),
                        (r, _) => r,
                    };
                    let us = t0.elapsed().as_micros() as u64;
                    let refusal = r.as_ref().err().map(|e| format!("{e:?}"));
                    send(&w, &match r {
                        Ok(p) => frame(Kind::Resp, h.req_id, h.op, &p),
                        Err(e) => frame(Kind::Err, h.req_id, h.op, &enc(&e)),
                    })?;
                    if let Some(f) = &self.audit {
                        let (op_name, right) = self.names.get(&cur).copied().unwrap_or(("?", "?"));
                        let grant = who.rights.iter().find_map(|r| r.strip_prefix(GRANT_RIGHT)).unwrap_or("").to_string();
                        f(&CallRecord { api: A::NAME, op: h.op, op_name, right, caller: who.name.clone(), grant, ok: refusal.is_none(), refusal: refusal.unwrap_or_default(), us });
                    }
                }
                Kind::Sub => {
                    // an older caller: its stream id and request become the current ones; its Sink carries items down
                    let (cur, body_in) = match &adapter {
                        None => (h.op, None),
                        Some(a) => match a.sub_in(h.op, &buf) {
                            Ok((op, b)) => (op, Some(b)),
                            Err(e) => {
                                send(&w, &frame(Kind::Err, h.req_id, h.op, &enc(&e)))?;
                                continue;
                            }
                        },
                    };
                    let Some(st) = self.streams.get(&cur).cloned() else {
                        send(&w, &frame(Kind::Err, h.req_id, h.op, &enc(&Refusal::UnknownOp(h.op))))?;
                        continue;
                    };
                    let cancelled = Arc::new(AtomicBool::new(false));
                    open.lock().unwrap().insert(h.req_id, cancelled.clone());
                    let body = match body_in { Some(b) => b, None => std::mem::take(&mut buf) };
                    let down = adapter.clone().map(|a| (h.op, a));
                    let (who, w, open) = (who.clone(), w.clone(), open.clone());
                    std::thread::spawn(move || {
                        let r = st(&body, who, w.clone(), h.req_id, cancelled.clone(), down);
                        open.lock().unwrap().remove(&h.req_id);
                        if !cancelled.load(Ordering::Relaxed) {
                            let _ = send(&w, &match r {
                                Ok(()) => frame(Kind::End, h.req_id, h.op, &[]),
                                Err(e) => frame(Kind::Err, h.req_id, h.op, &enc(&e)),
                            });
                        }
                    });
                }
                Kind::End => {
                    if let Some(c) = open.lock().unwrap().remove(&h.req_id) {
                        c.store(true, Ordering::Relaxed);
                    }
                }
                _ => {}
            }
        }
    }
}

/// The server end of one open stream. `send` fails once the client has gone or cancelled: return then.
pub struct Sink<I> {
    w: Out,
    id: u64,
    op: u32,
    cancelled: Arc<AtomicBool>,
    down: Option<Down>,
    _i: PhantomData<fn(I)>,
}

impl<I: serde::Serialize> Sink<I> {
    pub fn send(&self, item: &I) -> Result<(), WireError> {
        if !self.is_open() {
            return Err(WireError::Closed);
        }
        let p = postcard::to_stdvec(item).map_err(|e| WireError::Decode(e.to_string()))?;
        let (op, p) = match &self.down {
            None => (self.op, p),
            Some((old, a)) => match a.item_out(*old, &p) {
                Ok(b) => (*old, b),
                // an item the caller's version cannot carry ends its stream with the typed reason
                Err(e) => {
                    self.cancelled.store(true, Ordering::Relaxed);
                    let _ = send(&self.w, &frame(Kind::Err, self.id, *old, &enc(&e)));
                    return Err(WireError::Refused(e));
                }
            },
        };
        send(&self.w, &frame(Kind::Item, self.id, op, &p)).inspect_err(|_| self.cancelled.store(true, Ordering::Relaxed))
    }

    pub fn is_open(&self) -> bool {
        !self.cancelled.load(Ordering::Relaxed)
    }
}

/// A blocking typed client: one call at a time per client (calls from several threads queue on a mutex).
/// Every call waits at most [`DEADLINE`]; after a timeout, drop the client and reconnect.
pub struct Client<A: Api> {
    s: Mutex<(BufReader<TcpStream>, TcpStream, Vec<u8>)>,
    next: AtomicU64,
    session: u64,
    /// Set when the server is an older version this client holds adapters for ([`Client::connect_older`]).
    adapt: Option<crate::adapt::ServerAdapter>,
    _a: PhantomData<fn() -> A>,
}

impl<A: Api> Client<A> {
    /// The tokio `Client::connect_older`, blocking: an older server this client holds adapters for is called through
    /// them (recognised by its Schema refusal or its wire-3 op table; the client then says Hello as that version).
    pub fn connect_older(addr: impl ToSocketAddrs, token: Vec<u8>, olders: crate::adapt::OlderServers) -> Result<Self, WireError> {
        Self::connect_older_opts(addr, token, &olders, DEADLINE)
    }

    fn connect_older_opts(addr: impl ToSocketAddrs, token: Vec<u8>, olders: &crate::adapt::OlderServers, wait: std::time::Duration) -> Result<Self, WireError> {
        let addr = addr.to_socket_addrs().map_err(io)?.next().ok_or(WireError::Io("no address".into()))?;
        let a = match Self::connect_as(addr, token.clone(), false, wait, None) {
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
        Self::connect_as(addr, token, false, wait, Some(a)).map(|(c, _)| c)
    }

    /// The server's version when this connection adapts to an older one; `None` when it is at ours.
    pub fn server_version(&self) -> Option<u32> {
        self.adapt.as_ref().map(|a| a.version())
    }

    pub fn connect(addr: impl ToSocketAddrs, token: Vec<u8>) -> Result<Self, WireError> {
        Self::connect_opts(addr, token, false, DEADLINE)
    }

    /// `spawn`: ask a door to start the cell if it does not run there; `wait`: how long the Hello answer may take.
    /// A pending `SchemaAt` (an update under way at the door) gets one retry waiting up to [`crate::DRIFT_WAIT`].
    pub fn connect_opts(addr: impl ToSocketAddrs, token: Vec<u8>, spawn: bool, wait: std::time::Duration) -> Result<Self, WireError> {
        let addr = addr.to_socket_addrs().map_err(io)?.next().ok_or(WireError::Io("no address".into()))?;
        match Self::connect_hello(addr, token.clone(), spawn, wait) {
            Err(WireError::Refused(r)) if r.update_pending() => {
                eprintln!("ce-wire: {}: {r:?}; one retry, waiting up to {:?}", A::NAME, crate::DRIFT_WAIT);
                Self::connect_hello(addr, token, spawn, crate::DRIFT_WAIT)
            }
            r => r,
        }
    }

    fn connect_hello(addr: SocketAddr, token: Vec<u8>, spawn: bool, wait: std::time::Duration) -> Result<Self, WireError> {
        Self::connect_as(addr, token, spawn, wait, None).map(|(c, _)| c)
    }

    /// One Hello, as `A` or (with `adapt`) as the older version it names; also returns the server's op table.
    fn connect_as(addr: SocketAddr, token: Vec<u8>, spawn: bool, wait: std::time::Duration, adapt: Option<crate::adapt::ServerAdapter>) -> Result<(Self, Vec<(u32, u64)>), WireError> {
        let s = TcpStream::connect_timeout(&addr, DEADLINE).map_err(io)?;
        let _ = s.set_nodelay(true);
        s.set_read_timeout(Some(wait)).map_err(io)?;
        let mut w = s.try_clone().map_err(io)?;
        let (version, schema, table) = match &adapt {
            Some(a) => (a.version(), a.schema(), a.table().to_vec()),
            None => (A::VERSION, A::SCHEMA, crate::op_hashes::<A>()),
        };
        let hello = Hello { api: A::NAME.into(), version, schema, token, spawn };
        let mut p = crate::hello_payload_ops(&hello, wait, &table).map_err(WireError::Decode)?;
        // provider proof: only when a verifier is installed; off = the same bytes as before
        let verify = crate::provider::verifier().map(|v| (v, crate::provider::new_ask()));
        if let Some((_, ask)) = &verify {
            crate::provider::append_ask(&mut p, ask);
        }
        w.write_all(&frame(Kind::Hello, 0, 0, &p)).map_err(io)?;
        let mut r = BufReader::new(s);
        let mut buf = Vec::new();
        let h = read_frame(&mut r, &mut buf)?;
        if h.kind != Kind::Hello {
            return Err(WireError::Decode("expected Hello answer".into()));
        }
        r.get_ref().set_read_timeout(Some(DEADLINE)).map_err(io)?;
        let (ans, theirs) = crate::split_answer(&buf).map_err(WireError::Decode)?;
        if let (Some((v, ask)), Refusal::Ok { .. }) = (&verify, &ans) {
            let ctx = crate::provider::Ctx { hello_api: &hello.api, schema, token: &hello.token, ask, peer: Some(addr) };
            let proof = crate::provider::proof_in_answer(&buf);
            v(&ctx, proof.as_deref()).map_err(|e| WireError::Refused(Refusal::Gate(format!("provider: {e}"))))?;
        }
        match ans {
            Refusal::Ok { session } => Ok((Client { s: Mutex::new((r, w, buf)), next: AtomicU64::new(1), session, adapt, _a: PhantomData }, theirs)),
            other => Err(WireError::Refused(other)),
        }
    }

    /// Connect to cell `A` wherever it runs, like the tokio `Client::by_name` (order in `find.rs`): this machine's
    /// door, net.find's replicas (failover), the mesh peers' doors at once, then this machine's door with spawn.
    /// While net.find knows a replica but none answers, the first three repeat with backoff for up to
    /// `find::RETRY_FOR` before the spawn.
    pub fn by_name(token: Vec<u8>) -> Result<Self, WireError> {
        Self::by_name_inner(token, None)
    }

    /// [`Client::by_name`], and a replica at an older version this client holds adapters for is called through them
    /// ([`Client::connect_older`]). The local spawn, last, starts this machine's own build.
    pub fn by_name_older(token: Vec<u8>, olders: crate::adapt::OlderServers) -> Result<Self, WireError> {
        Self::by_name_inner(token, Some(olders))
    }

    fn dial(addr: String, token: Vec<u8>, wait: std::time::Duration, olders: Option<&crate::adapt::OlderServers>) -> Result<Self, WireError> {
        match olders {
            Some(o) => Self::connect_older_opts(addr.as_str(), token, o, wait),
            None => Self::connect_opts(addr.as_str(), token, false, wait),
        }
    }

    fn by_name_inner(token: Vec<u8>, olders: Option<crate::adapt::OlderServers>) -> Result<Self, WireError> {
        let older_schemas = olders.as_ref().map(|o| o.schemas()).unwrap_or_default();
        let port = crate::door_port();
        let local = SocketAddr::from(([127, 0, 0, 1], port));
        let mut tried = Vec::new();
        let mut find_err = None;
        // net.find knew a replica of this schema: worth retrying through a link blip before spawning here.
        let mut known = false;
        let start = std::time::Instant::now();
        let away = crate::find::pinned_away(A::NAME);
        let rd = if away.is_some() { crate::find::REMOTE_DEADLINE } else { DEADLINE };
        for round in 0.. {
            match Self::dial(local.to_string(), token.clone(), DEADLINE, olders.as_ref()) {
                Ok(c) => return Ok(c),
                Err(e) => tried.push(format!("door {local}: {e:?}")),
            }
            match crate::find::find_blocking(A::NAME, crate::find::major::<A>()) {
                Some(Ok(reply)) => {
                    for a in crate::find::usable_with::<A>(&reply, &older_schemas) {
                        match Self::dial(a.clone(), token.clone(), rd, olders.as_ref()) {
                            Ok(c) => return Ok(c),
                            Err(e) => tried.push(format!("replica {a}: {e:?}")),
                        }
                    }
                    known |= !crate::find::usable_with::<A>(&reply, &older_schemas).is_empty();
                    if reply.replicas.is_empty() {
                        tried.push("net.find: no replica".into());
                    }
                }
                Some(Err(e)) => {
                    tried.push(format!("net.find: {e:?}"));
                    find_err = Some(e);
                }
                None => tried.push("net.find: no finder answered".into()),
            }
            let peers = crate::candidates(A::NAME);
            if !peers.is_empty() {
                let (tx, rx) = std::sync::mpsc::channel();
                for ip in peers.iter().copied() {
                    let (tx, t, o) = (tx.clone(), token.clone(), olders.clone());
                    std::thread::spawn(move || {
                        let _ = tx.send(Self::dial(SocketAddr::new(ip, port).to_string(), t, rd, o.as_ref()));
                    });
                }
                drop(tx);
                for r in rx {
                    match r {
                        Ok(c) => return Ok(c),
                        Err(e) => tried.push(format!("peer: {e:?}")),
                    }
                }
            }
            let next = if away.is_some() { crate::find::remote_wait(start) } else { crate::find::retry_wait(start, round).filter(|_| known) };
            match next {
                Some(w) => std::thread::sleep(w),
                None => break,
            }
        }
        if let Some(why) = away {
            tried.push(format!("not runnable here ({why}), so no local spawn: the remote replica did not answer for {}s", crate::find::REMOTE_RETRY_FOR.as_secs()));
            return Err(crate::find::unreachable::<A>(find_err, tried, WireError::Timeout));
        }
        Self::connect_opts(local, token, true, crate::SPAWN_WAIT + DEADLINE).map_err(|e| crate::find::unreachable::<A>(find_err, tried, e))
    }

    /// How long a call waits for its answer (default `DEADLINE`).
    pub fn set_deadline(&self, d: std::time::Duration) {
        let _ = self.s.lock().unwrap().0.get_ref().set_read_timeout(Some(d));
    }

    /// This connection's session key, for [`DatagramSocket::send`].
    pub fn session(&self) -> u64 {
        self.session
    }

    pub fn call<O: Op<Api = A>>(&self, req: &O::Req) -> Result<O::Resp, WireError> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let p = postcard::to_stdvec(req).map_err(|e| WireError::Decode(e.to_string()))?;
        let mut g = self.s.lock().unwrap();
        let (r, w, buf) = &mut *g;
        // an op with its own deadline (`deadline_ms` in api!) widens the read timeout for this call only
        let before = r.get_ref().read_timeout().ok().flatten();
        let wide = O::DEADLINE_MS.is_some() && {
            let d = crate::op_deadline::<O>(before.unwrap_or(DEADLINE));
            r.get_ref().set_read_timeout(Some(d)).is_ok()
        };
        let out = Self::exchange::<O>(r, w, buf, id, &p, self.adapt.as_ref());
        if wide {
            let _ = r.get_ref().set_read_timeout(before);
        }
        out
    }

    fn exchange<O: Op<Api = A>>(r: &mut BufReader<TcpStream>, w: &mut TcpStream, buf: &mut Vec<u8>, id: u64, p: &[u8], adapt: Option<&crate::adapt::ServerAdapter>) -> Result<O::Resp, WireError> {
        let (op, p) = match adapt {
            Some(a) => a.req_out(O::ID, p).map_err(WireError::Refused)?,
            None => (O::ID, p.to_vec()),
        };
        w.write_all(&frame(Kind::Req, id, op, &p)).map_err(|_| WireError::Closed)?;
        loop {
            let h = read_frame(r, buf)?;
            if h.req_id != id {
                continue;
            }
            return match h.kind {
                Kind::Resp => match adapt {
                    Some(a) => postcard::from_bytes(&a.resp_in(O::ID, buf).map_err(WireError::Refused)?).map_err(|e| WireError::Decode(e.to_string())),
                    None => postcard::from_bytes(buf).map_err(|e| WireError::Decode(e.to_string())),
                },
                Kind::Err => Err(WireError::Refused(postcard::from_bytes(buf).map_err(|e| WireError::Decode(e.to_string()))?)),
                _ => continue,
            };
        }
    }
}

/// One received datagram, decoded only as the op it claims to be.
pub struct Datagram {
    pub from: SocketAddr,
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

/// Typed UDP datagrams, blocking: same format and rules as the tokio `DatagramSocket` (session key, newest seq per
/// (sender, op) wins, stale and stranger datagrams dropped silently, 1200 B max).
pub struct DatagramSocket<A: Api> {
    sock: UdpSocket,
    seq: AtomicU64,
    last: HashMap<(SocketAddr, u32), u64>,
    sessions: Option<Sessions>,
    buf: Vec<u8>,
    _a: PhantomData<fn() -> A>,
}

impl<A: Api> DatagramSocket<A> {
    /// `sessions`: the receiving server's gated callers; `None` for a send-only socket.
    pub fn bind(addr: impl ToSocketAddrs, sessions: Option<Sessions>) -> std::io::Result<Self> {
        Ok(DatagramSocket { sock: UdpSocket::bind(addr)?, seq: AtomicU64::new(1), last: HashMap::new(), sessions, buf: vec![0; 2048], _a: PhantomData })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    /// The underlying socket, e.g. to set a read timeout.
    pub fn socket(&self) -> &UdpSocket {
        &self.sock
    }

    pub fn send<O: Op<Api = A>>(&self, to: SocketAddr, session: u64, msg: &O::Req) -> Result<u64, WireError> {
        let mut p = session.to_le_bytes().to_vec();
        p.extend(postcard::to_stdvec(msg).map_err(|e| WireError::Decode(e.to_string()))?);
        if p.len() > crate::MAX_DATAGRAM {
            return Err(WireError::Decode(format!("datagram {} B > {} B (nm0 MTU 1280)", p.len(), crate::MAX_DATAGRAM)));
        }
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        self.sock.send_to(&frame(Kind::Datagram, seq, O::ID, &p), to).map_err(io)?;
        Ok(seq)
    }

    /// Next fresh datagram from a gated caller that holds the op's right (`rights!`); everything else is dropped.
    pub fn recv(&mut self, rights: &HashMap<u32, &'static str>) -> Result<Datagram, WireError> {
        loop {
            let (n, from) = self.sock.recv_from(&mut self.buf).map_err(|e| match e.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => WireError::Timeout,
                _ => io(e),
            })?;
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

#[cfg(feature = "blocking-door")]
impl<A: Api> Server<A> {
    /// Serve through this machine's door without tokio: register over the door's Unix socket, then run every
    /// connection the door hands over (SCM_RIGHTS) on its own thread. Returns when the door closes the registration
    /// (door restart or `ce-door stop <api>`), so a cell's `main` ends with it.
    pub fn serve_door(self) -> Result<(), WireError> {
        let sock = std::env::var("CE_DOOR_SOCK").map(std::path::PathBuf::from).unwrap_or_else(|_| {
            std::path::PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/".into())).join(".ce/wire-door.sock")
        });
        self.serve_door_at(&sock)
    }

    /// [`Self::serve_door`] with an explicit door socket.
    pub fn serve_door_at(self, sock: &std::path::Path) -> Result<(), WireError> {
        self.serve_door_at_as(sock, "")
    }

    /// [`Self::serve_door`] as instance `name` of the api (`<api>#<name>`, see `ce_wire::instance_key`).
    pub fn serve_door_as(self, name: &str) -> Result<(), WireError> {
        let sock = std::env::var("CE_DOOR_SOCK").map(std::path::PathBuf::from).unwrap_or_else(|_| {
            std::path::PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/".into())).join(".ce/wire-door.sock")
        });
        self.serve_door_at_as(&sock, name)
    }

    /// [`Self::serve_door_at`] as instance `name`.
    pub fn serve_door_at_as(self, sock: &std::path::Path, name: &str) -> Result<(), WireError> {
        let key = crate::instance_key(A::NAME, name);
        if !crate::valid_key(&key) {
            return Err(WireError::Io(format!("{key}: not a valid instance name")));
        }
        use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
        use std::os::fd::{AsRawFd, FromRawFd, RawFd};
        use std::os::unix::net::UnixStream;
        let io = |e: std::io::Error| WireError::Io(e.to_string());
        let mut ctl = UnixStream::connect(sock).map_err(|e| WireError::Io(format!("door {}: {e}", sock.display())))?;
        let apo = crate::apo_field(self.apoptosis.as_ref().map_or(crate::APOPTOSIS_MS, |a| a.0));
        ctl.write_all(format!("REGISTER {} {:016x} {}{}{} wire={}{}{apo}\n", key, A::SCHEMA, std::process::id(), crate::rev_field(), crate::adapt::accepts_field::<A>(&self.olders), crate::WIRE, crate::ops_field::<A>()).as_bytes()).map_err(io)?;
        let me = Arc::new(self);
        let mut buf = vec![0u8; 4 + 64 * 1024];
        loop {
            let (n, fd) = {
                let mut cspace = nix::cmsg_space!([RawFd; 1]);
                let mut iov = [std::io::IoSliceMut::new(&mut buf)];
                let msg = recvmsg::<()>(ctl.as_raw_fd(), &mut iov, Some(&mut cspace), MsgFlags::empty())
                    .map_err(|e| WireError::Io(e.to_string()))?;
                let mut fd = None;
                for c in msg.cmsgs().map_err(|e| WireError::Io(e.to_string()))? {
                    if let ControlMessageOwned::ScmRights(v) = c {
                        fd = v.first().copied();
                    }
                }
                (msg.bytes, fd)
            };
            if n == 0 {
                return Ok(()); // the door closed the registration
            }
            let Some(fd) = fd else {
                // no socket: only an apoptosis request is one (src/apoptosis.rs). Run the routine within its time,
                // answer, and read on until the door closes the registration.
                let word = if n >= 4 { u32::from_le_bytes(buf[..4].try_into().unwrap()) } else { 0 };
                let len = (word & !crate::APO_MARK) as usize;
                if word & crate::APO_MARK == 0 || len > 64 * 1024 {
                    return Err(WireError::Io("handoff without a socket".into()));
                }
                let mut got = n;
                while got < 4 + len {
                    let k = ctl.read(&mut buf[got..4 + len]).map_err(io)?;
                    if k == 0 {
                        return Ok(());
                    }
                    got += k;
                }
                let req: crate::ApoptosisReq = postcard::from_bytes(&buf[4..4 + len]).unwrap_or_default();
                let r = match me.apoptosis.clone() {
                    None => Ok(crate::Saved::default()),
                    Some((ms, f)) => {
                        let ms = if req.deadline_ms == 0 { ms } else { req.deadline_ms.min(ms) };
                        let (tx, rx) = std::sync::mpsc::channel();
                        std::thread::spawn(move || {
                            let _ = tx.send(f(req));
                        });
                        rx.recv_timeout(std::time::Duration::from_millis(ms as u64)).unwrap_or_else(|_| Err(format!("not done in {ms} ms")))
                    }
                };
                let _ = ctl.write_all(&crate::apo_frame(0, &r));
                continue;
            };
            // SAFETY: fd was just received via SCM_RIGHTS and nothing else in this process owns it.
            let s = unsafe { TcpStream::from_raw_fd(fd) };
            unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFD, nix::libc::FD_CLOEXEC) };
            // The door's copy was non-blocking (tokio), and that flag belongs to the shared file description.
            s.set_nonblocking(false).map_err(io)?;
            if n < 4 {
                return Err(WireError::Io("short handoff header".into()));
            }
            let len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
            if len > 64 * 1024 {
                return Err(WireError::Io("handoff too big".into()));
            }
            let mut got = n;
            while got < 4 + len {
                let k = ctl.read(&mut buf[got..4 + len]).map_err(io)?;
                if k == 0 {
                    return Err(WireError::Io("door closed mid handoff".into()));
                }
                got += k;
            }
            let hello = buf[4..4 + len].to_vec();
            let me = me.clone();
            std::thread::spawn(move || me.serve_conn(s, Some(hello)));
        }
    }
}
