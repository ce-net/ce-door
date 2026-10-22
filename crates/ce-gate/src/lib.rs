//! ce-gate: who may open a ce-wire connection, decided by ce-cap (D11a).
//!
//! Client: `Hello.token = ce_gate::proof::<A>(&identity, &chain)`. The proof is postcard
//! `Proof { requester, unix_ms, nonce, chain, sig }`, where `sig` is the requester's ed25519 signature over
//! `"ce-wire-hello-v1" | api | schema | unix_ms | nonce | requester | chain` (the `Signed` struct, postcard).
//!
//! Cell: `Server::new(ce_gate::Gate::<A>::new(self_id, roots).into_fn())`. The gate checks, in order:
//! 1. the proof decodes and the signature verifies against `requester` (proves the caller holds that node key);
//! 2. `|now - unix_ms| <= 30 s` and the nonce was not seen in the last 60 s (no replay);
//! 3. the ce-cap chain roots at this node or an accepted root, every link is signed, unexpired, not revoked,
//!    applies to this node, attenuates its parent, and its leaf is held by `requester` (`ce_cap::authorize`);
//! 4. the caller gets every right of `A::RIGHTS` that the leaf's abilities cover (`ce_cap::ability_covers`:
//!    exact, `*`, or `domain:*`). No covered right at all: refused.
//!
//! v2 (`proof2`): the token is [`PROOF2_MAGIC`] + postcard [`Proof2`], whose chain is hash-id caps
//! ([`cap_hash::Cap`]) bound to this api and its schema hash; the gate runs [`cap_hash::verify_chain`] in place of
//! step 3. v1 tokens are still accepted (counted by [`legacy_accepted`]) unless [`Gate::require_v2`] or [`v2_only`].
//!
//! Rights are decided once per connection. A cap that expires or is revoked mid-connection keeps working until the
//! connection closes; cells that need sooner cut-off set a max connection age.
pub use ce_cap;
pub use ce_identity;
use ce_cap::{ability_covers, authorize, decode_chain_bytes, SignedCapability};
use ce_identity::{Identity, NodeId};
use ce_wire::{Api, Caller, Hello};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_SKEW_MS: u64 = 30_000;
pub const NONCE_TTL_MS: u64 = 60_000;
/// Nonces kept at most; a flood beyond this is refused rather than growing memory.
pub const MAX_NONCES: usize = 200_000;
const DOMAIN: &str = "ce-wire-hello-v1";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Proof {
    pub requester: NodeId,
    pub unix_ms: u64,
    pub nonce: [u8; 16],
    /// `ce_cap::encode_chain_bytes` of the caller's chain.
    pub chain: Vec<u8>,
    pub sig: Vec<u8>,
}

#[derive(Serialize)]
struct Signed<'a> {
    domain: &'a str,
    api: &'a str,
    schema: u64,
    unix_ms: u64,
    nonce: [u8; 16],
    requester: NodeId,
    chain: &'a [u8],
}

/// First bytes of a v2 Hello token ([`proof2`]). A v1 token starts with the requester's 32-byte key, so a v1 token
/// that begins with these 8 bytes is a 2^-64 accident; a token with them is read as v2 only (never retried as v1).
pub const PROOF2_MAGIC: &[u8; 8] = b"cecap2\0\x01";
const DOMAIN2: &str = "ce-wire-hello-v2";

/// The v2 Hello proof: a chain of hash-id caps ([`cap_hash::Cap`]) and the requester's signature over the api,
/// schema, time, nonce, requester and the chain's ids (each id commits to its whole body).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Proof2 {
    pub requester: NodeId,
    pub unix_ms: u64,
    pub nonce: [u8; 16],
    pub chain: Vec<cap_hash::Cap>,
    pub sig: Vec<u8>,
}

#[derive(Serialize)]
struct Signed2<'a> {
    domain: &'a str,
    api: &'a str,
    schema: u64,
    unix_ms: u64,
    nonce: [u8; 16],
    requester: NodeId,
    ids: Vec<cap_hash::CapHash>,
}

fn signed2_bytes(api: &str, schema: u64, p: &Proof2) -> Vec<u8> {
    let ids = p.chain.iter().map(|c| c.id).collect();
    postcard::to_stdvec(&Signed2 { domain: DOMAIN2, api, schema, unix_ms: p.unix_ms, nonce: p.nonce, requester: p.requester, ids })
        .expect("postcard to vec")
}

/// The v2 Hello token for API `A`: proof that this node key holds the hash-id `chain`.
pub fn proof2<A: Api>(id: &Identity, chain: &[cap_hash::Cap]) -> Vec<u8> {
    proof2_for(id, chain, A::NAME, A::SCHEMA)
}

/// [`proof2`] for instance `name` of API `A`.
pub fn proof2_as<A: Api>(id: &Identity, chain: &[cap_hash::Cap], name: &str) -> Vec<u8> {
    proof2_for(id, chain, &ce_wire::instance_key(A::NAME, name), A::SCHEMA)
}

/// [`proof2`] without the type.
pub fn proof2_for(id: &Identity, chain: &[cap_hash::Cap], api: &str, schema: u64) -> Vec<u8> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).expect("os random");
    let mut p = Proof2 { requester: id.node_id(), unix_ms: now_ms(), nonce, chain: chain.to_vec(), sig: vec![] };
    p.sig = id.sign(&signed2_bytes(api, schema, &p)).to_vec();
    let mut out = PROOF2_MAGIC.to_vec();
    out.extend(postcard::to_stdvec(&p).expect("postcard to vec"));
    out
}

/// A Hello token decoded and its requester signature verified.
enum Token {
    V1(Proof),
    V2(Proof2),
}

impl Token {
    fn requester(&self) -> &NodeId {
        match self {
            Token::V1(p) => &p.requester,
            Token::V2(p) => &p.requester,
        }
    }
    fn unix_ms(&self) -> u64 {
        match self {
            Token::V1(p) => p.unix_ms,
            Token::V2(p) => p.unix_ms,
        }
    }
    fn nonce(&self) -> [u8; 16] {
        match self {
            Token::V1(p) => p.nonce,
            Token::V2(p) => p.nonce,
        }
    }
}

/// Decode `h.token` (v2 when it starts with [`PROOF2_MAGIC`], else v1) and verify the requester's signature over
/// the Hello's api and schema.
fn open_token(h: &Hello) -> Result<Token, String> {
    let (t, bytes) = match h.token.strip_prefix(PROOF2_MAGIC.as_slice()) {
        Some(rest) => {
            let p: Proof2 = postcard::from_bytes(rest).map_err(|_| "token is not a ce-gate v2 proof".to_string())?;
            let b = signed2_bytes(&h.api, h.schema, &p);
            (Token::V2(p), b)
        }
        None => {
            let p: Proof = postcard::from_bytes(&h.token).map_err(|_| "token is not a ce-gate proof".to_string())?;
            let b = signed_bytes(&h.api, h.schema, &p);
            (Token::V1(p), b)
        }
    };
    let sig = match &t {
        Token::V1(p) => &p.sig,
        Token::V2(p) => &p.sig,
    };
    let sig: [u8; 64] = sig.as_slice().try_into().map_err(|_| "signature is not 64 bytes".to_string())?;
    ce_identity::verify(t.requester(), &bytes, &sig).map_err(|_| "bad hello signature".to_string())?;
    Ok(t)
}

/// v1 (ce-cap chain, not bound to an api schema) Hellos accepted by every gate in this process since start.
static LEGACY_ACCEPTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many v1 Hellos the gates of this process accepted: the count that must reach zero before a cell sets
/// [`Gate::require_v2`].
pub fn legacy_accepted() -> u64 {
    LEGACY_ACCEPTED.load(std::sync::atomic::Ordering::Relaxed)
}

/// True when `api` refuses v1 caps: `$CE_GATE_REQUIRE_V2` is `1`/`all` or a comma list naming it, or a line of
/// `~/.config/ce-wire/v2-only` names it (or is `*`).
pub fn v2_only(api: &str) -> bool {
    let names = |s: &str| s.split([',', '\n']).map(|l| l.split('#').next().unwrap_or("").trim().to_string()).any(|l| l == api || l == "*" || l == "all" || l == "1");
    std::env::var("CE_GATE_REQUIRE_V2").is_ok_and(|v| names(&v))
        || std::fs::read_to_string(ce_wire::peers_file().with_file_name("v2-only")).is_ok_and(|f| names(&f))
}

/// Unix time in ms. On wasm32 in a browser `SystemTime::now()` panics, so read the JS clock there.
#[cfg(not(target_arch = "wasm32"))]
fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[cfg(target_arch = "wasm32")]
fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

fn signed_bytes(api: &str, schema: u64, p: &Proof) -> Vec<u8> {
    postcard::to_stdvec(&Signed { domain: DOMAIN, api, schema, unix_ms: p.unix_ms, nonce: p.nonce, requester: p.requester, chain: &p.chain })
        .expect("postcard to vec")
}

/// The Hello token for API `A`: proof that this node key holds `chain`.
pub fn proof<A: Api>(id: &Identity, chain: &[SignedCapability]) -> Vec<u8> {
    proof_for(id, chain, A::NAME, A::SCHEMA)
}

/// [`proof`] without the type, for generated or dynamic clients.
pub fn proof_for(id: &Identity, chain: &[SignedCapability], api: &str, schema: u64) -> Vec<u8> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).expect("os random");
    let mut p = Proof { requester: id.node_id(), unix_ms: now_ms(), nonce, chain: ce_cap::encode_chain_bytes(chain), sig: vec![] };
    p.sig = id.sign(&signed_bytes(api, schema, &p)).to_vec();
    postcard::to_stdvec(&p).expect("postcard to vec")
}

/// The Hello token for instance `name` of API `A` (`obs.source#wx.metar`, `ce_wire::instance_key`): the proof is
/// signed over the instance name, so it cannot be replayed at another instance. Rights stay the api's.
pub fn proof_as<A: Api>(id: &Identity, chain: &[SignedCapability], name: &str) -> Vec<u8> {
    proof_for(id, chain, &ce_wire::instance_key(A::NAME, name), A::SCHEMA)
}

/// A grant token as `ce-iam grant --to <node id hex> --action <right> --nonce N` prints it (hex chain).
pub fn chain_from_hex(token: &str) -> Result<Vec<SignedCapability>, String> {
    ce_cap::decode_chain(token).map_err(|e| e.to_string())
}

/// This node's CE identity: `<ce_wire::ce_data_dir()>/identity` (the ce node's own key; macOS keeps it under
/// ~/Library/Application Support/ce, so reading ~/.local/share/ce there minted a stray identity).
pub fn node_identity() -> std::io::Result<Identity> {
    Identity::load_or_generate(&ce_dir().join("identity")).map_err(|e| std::io::Error::other(e.to_string()))
}

#[cfg(not(target_arch = "wasm32"))]
pub mod audit;
pub mod cap_hash;
/// Provider proof: the serving side of cap v2. Off unless a process installs it.
pub mod provider;

fn ce_dir() -> PathBuf {
    ce_wire::ce_data_dir()
}

/// The ce node's revocation list (`revocations.json`), re-read when its mtime changes.
struct Revocations {
    path: PathBuf,
    mtime: Option<SystemTime>,
    set: HashSet<(NodeId, u64)>,
}

impl Revocations {
    fn refresh(&mut self) {
        let m = std::fs::metadata(&self.path).and_then(|m| m.modified()).ok();
        if m == self.mtime {
            return;
        }
        self.mtime = m;
        #[derive(Deserialize)]
        struct R {
            issuer: NodeId,
            nonce: u64,
        }
        #[derive(Deserialize)]
        struct F {
            records: Vec<R>,
        }
        self.set = std::fs::read(&self.path)
            .ok()
            .and_then(|b| serde_json::from_slice::<F>(&b).ok())
            .map(|f| f.records.into_iter().map(|r| (r.issuer, r.nonce)).collect())
            .unwrap_or_default();
    }
}

/// A ce-cap gate for the cells of API `A`.
pub struct Gate<A: Api> {
    self_id: NodeId,
    roots: Vec<NodeId>,
    /// Built from [`mesh_roots`]: the roots follow the peers and roots files (re-read every `MESH_ROOTS_EVERY`), so a
    /// node that joins the mesh is rooted without restarting every cell.
    live: Option<Mutex<(std::time::Instant, Vec<NodeId>)>>,
    tags: Vec<String>,
    nonces: Mutex<HashMap<[u8; 16], u64>>,
    revoked: Mutex<Revocations>,
    /// Refuse v1 (ce-cap) chains: only hash-id caps bound to this api and schema open the cell.
    require_v2: bool,
    /// This cell's [`cap_hash::cell_id`], for caps pinned to one build.
    cell: Option<cap_hash::CapHash>,
    legacy_warned: std::sync::atomic::AtomicBool,
    _a: PhantomData<fn() -> A>,
}

impl<A: Api> Gate<A> {
    /// `self_id`: this node's id (caps must apply to it); `roots`: authorities besides this node itself.
    /// A `roots` equal to [`mesh_roots`] now becomes [`mesh_roots_for`] this api, kept current; any other set is fixed.
    /// An [`own_key_only`] api drops every mesh root from `roots` (whatever the cell passed) and follows only the roots
    /// lines that name it.
    pub fn new(self_id: NodeId, roots: Vec<NodeId>) -> Self {
        let mesh = mesh_roots();
        let (roots, live) = if own_key_only(A::NAME) {
            (roots.into_iter().filter(|r| !mesh.contains(r)).collect(), true)
        } else if roots == mesh {
            (vec![], true)
        } else {
            (roots, false)
        };
        let live = live.then(|| Mutex::new((std::time::Instant::now(), mesh_roots_for(A::NAME))));
        Gate {
            self_id,
            roots,
            live,
            tags: vec![],
            nonces: Mutex::default(),
            revoked: Mutex::new(Revocations { path: ce_dir().join("revocations.json"), mtime: None, set: HashSet::new() }),
            require_v2: v2_only(A::NAME),
            cell: None,
            legacy_warned: Default::default(),
            _a: PhantomData,
        }
    }

    /// Refuse v1 caps for this cell (also on when [`v2_only`] names the api).
    pub fn require_v2(mut self) -> Self {
        self.require_v2 = true;
        self
    }

    /// This cell's build: its [`cap_hash::cell_id`] is `(A::NAME, A::SCHEMA, build_rev, signer)`, so a cap pinned to
    /// it opens this build only. Without it, every cell-pinned cap is refused.
    pub fn cell(mut self, build_rev: &str, signer: &NodeId) -> Self {
        self.cell = Some(cap_hash::cell_id(A::NAME, A::SCHEMA, build_rev, signer));
        self
    }

    /// This cell's id, when [`Self::cell`] set it.
    pub fn cell_id(&self) -> Option<cap_hash::CapHash> {
        self.cell
    }

    /// This node's ce tags, for caps scoped `tag:<t>`.
    pub fn tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// The gate as the `Fn(&Hello) -> Result<Caller, String>` that `Server::new` takes (tokio or blocking).
    pub fn into_fn(self) -> impl Fn(&Hello) -> Result<Caller, String> + Send + Sync + 'static {
        let g = Arc::new(self);
        move |h: &Hello| g.check(h, now_ms())
    }

    pub fn check(&self, h: &Hello, now: u64) -> Result<Caller, String> {
        let t = open_token(h)?;
        if now.abs_diff(t.unix_ms()) > MAX_SKEW_MS {
            // Include the caller's short id: under load, different callers refused at one instant show
            // DIFFERENT deltas (each hello aged a different amount between mint and arrival) = connect
            // latency, not a clock offset; the SAME delta for every caller = a real clock skew. The
            // sign of the delta tells which side is ahead (positive = the hello arrived stale/aged).
            let who = hex(t.requester());
            let who = &who[..who.len().min(8)];
            return Err(format!("hello from {who} clock off by {} ms (max {MAX_SKEW_MS})", now as i128 - t.unix_ms() as i128));
        }
        if matches!(t, Token::V1(_)) && self.require_v2 {
            return Err(format!("{} takes hash-id (v2) caps only", A::NAME));
        }
        {
            let mut n = self.nonces.lock().unwrap();
            if n.len() >= MAX_NONCES / 2 {
                n.retain(|_, t| now.saturating_sub(*t) <= NONCE_TTL_MS);
            }
            if n.len() >= MAX_NONCES {
                return Err("too many hellos, try again".into());
            }
            if n.insert(t.nonce(), now).is_some() {
                return Err("replayed hello".into());
            }
        }
        // A refused Hello gives its nonce back, so a client that retries the same proof at another door of the same
        // process sees the real reason, not "replayed hello"; only accepted nonces guard against replay.
        let r = match &t {
            Token::V1(p) => self.rights(p, now).inspect(|c| self.count_legacy(c)),
            Token::V2(p) => self.rights2(h, p, now),
        };
        if r.is_err() {
            self.nonces.lock().unwrap().remove(&t.nonce());
        }
        r
    }

    /// Count an accepted v1 Hello; say so on stderr the first time and every 1024th after.
    fn count_legacy(&self, c: &Caller) {
        let n = LEGACY_ACCEPTED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if !self.legacy_warned.swap(true, std::sync::atomic::Ordering::Relaxed) || n % 1024 == 0 {
            let who = &c.name[..c.name.len().min(8)];
            eprintln!("ce-gate: {} accepted a v1 cap (no api/schema binding) from {who}; {} v1 hellos so far", A::NAME, n + 1);
        }
    }

    /// Rights from a v2 chain: [`cap_hash::verify_chain`] against this api, its schemas and this node's roots.
    fn rights2(&self, h: &Hello, p: &Proof2, now: u64) -> Result<Caller, String> {
        let mut schemas = vec![A::SCHEMA];
        schemas.extend_from_slice(A::ACCEPTS);
        let serving = cap_hash::Serving { self_id: &self.self_id, tags: &self.tags, api: A::NAME, hello_api: &h.api, schemas: &schemas, cell: self.cell };
        let mut rv = self.revoked.lock().unwrap();
        rv.refresh();
        let is_revoked = |i: &NodeId, n: u64| rv.set.contains(&(*i, n));
        let mut r = cap_hash::verify_chain(&serving, &self.roots_now(), now / 1000, &p.requester, &p.chain, &is_revoked).map(|_| ());
        if r.as_ref().is_err_and(|e| e.contains("root")) {
            if let Some(roots) = self.roots_at(true) {
                r = cap_hash::verify_chain(&serving, &roots, now / 1000, &p.requester, &p.chain, &is_revoked).map(|_| ());
            }
        }
        r?;
        let leaf = &p.chain.last().ok_or("empty chain")?;
        shape_rights::<A>(&p.requester, &leaf.body.ops, leaf.body.caveats.path_prefix.as_deref(), hex(&leaf.id[..8]))
    }

    /// The roots to check against: the fixed set plus the mesh set at most `MESH_ROOTS_EVERY` old.
    fn roots_now(&self) -> Vec<NodeId> {
        self.roots_at(false).unwrap_or_default()
    }

    /// [`Self::roots_now`]; with `refused`, re-read the mesh set now unless it was read in the last
    /// [`ROOTS_ON_REFUSAL_EVERY`], and return None when nothing was re-read (so the caller does not retry).
    fn roots_at(&self, refused: bool) -> Option<Vec<NodeId>> {
        let Some(l) = &self.live else { return (!refused).then(|| self.roots.clone()) };
        let mut g = l.lock().unwrap();
        let every = if refused {
            ROOTS_ON_REFUSAL_EVERY
        } else {
            std::env::var("CE_GATE_ROOTS_EVERY_MS").ok().and_then(|v| v.parse().ok()).map_or(MESH_ROOTS_EVERY, std::time::Duration::from_millis)
        };
        if g.0.elapsed() >= every {
            *g = (std::time::Instant::now(), mesh_roots_for(A::NAME));
        } else if refused {
            return None;
        }
        Some(self.roots.iter().chain(&g.1).copied().collect())
    }

    fn rights(&self, p: &Proof, now: u64) -> Result<Caller, String> {
        let chain = decode_chain_bytes(&p.chain).map_err(|e| format!("chain: {e}"))?;
        let Some(first) = A::RIGHTS.first() else { return Err(format!("{} declares no rights", A::NAME)) };
        let mut rv = self.revoked.lock().unwrap();
        rv.refresh();
        let is_revoked = |i: &NodeId, n: u64| rv.set.contains(&(*i, n));
        // One full chain check; the error for "valid chain, wrong ability" is fine, we test abilities below.
        let roots = self.roots_now();
        let mut r = authorize(&self.self_id, &roots, &self.tags, now / 1000, &p.requester, first, &chain, &is_revoked);
        // a node that joined the mesh since the last read: re-read the peers/roots files now instead of refusing it
        // for up to MESH_ROOTS_EVERY (a freshly joined node was refused by a cell until its door restarted)
        if r.as_ref().is_err_and(|e| e.contains("root")) {
            if let Some(roots) = self.roots_at(true) {
                r = authorize(&self.self_id, &roots, &self.tags, now / 1000, &p.requester, first, &chain, &is_revoked);
            }
        }
        if let Err(e) = r {
            if !e.starts_with("capability does not grant") {
                return Err(e);
            }
        }
        let leaf = &chain.last().ok_or("empty chain")?.cap;
        // the grant this call came in with, for the audit row: the first 16 hex of sha256 over the chain bytes
        shape_rights::<A>(&p.requester, &leaf.abilities, leaf.caveats.path_prefix.as_deref(), grant_id(&p.chain))
    }
}

/// The caller's rights from a verified leaf: every right of `A::RIGHTS` its abilities cover, the abilities as
/// `ability:` entries, the leaf's path prefix and the grant id. No covered right: refused.
fn shape_rights<A: Api>(requester: &NodeId, abilities: &[String], path_prefix: Option<&str>, grant: String) -> Result<Caller, String> {
    let mut rights: Vec<String> =
        A::RIGHTS.iter().filter(|r| abilities.iter().any(|a| ability_covers(a, r))).map(|r| r.to_string()).collect();
    rights.sort();
    rights.dedup();
    if rights.is_empty() {
        return Err(format!("capability grants none of {:?}", A::RIGHTS));
    }
    // `caveat:` entries are written only by this gate from the verified leaf: a right of that shape in the API or
    // in the cap's abilities must never reach the cell as one.
    rights.retain(|r| !r.starts_with("caveat:") && !r.starts_with("ability:") && !r.starts_with(ce_wire::GRANT_RIGHT));
    rights.extend(abilities.iter().take(64).map(|a| format!("{}{a}", ce_wire::ABILITY_RIGHT)));
    // The leaf is no broader than its parents (the chain check verified the attenuation): its prefix is the effective one.
    if let Some(pp) = path_prefix {
        rights.push(format!("{}{pp}", ce_wire::PATH_PREFIX_RIGHT));
    }
    rights.push(format!("{}{grant}", ce_wire::GRANT_RIGHT));
    Ok(Caller { name: hex(requester), rights })
}

/// The id an audit row names a grant by: the first 16 hex of sha256 over the cap chain bytes (same chain, same id).
pub fn grant_id(chain: &[u8]) -> String {
    use sha2::Digest;
    hex(&sha2::Sha256::digest(chain)[..8])
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The door's spawn gate (`ce_wire::run_door_gated`): a Hello may start a cell that is not running only if its proof
/// is signed, fresh, and carries a ce-cap chain rooted at this node or `roots` whose leaf grants `<api>:spawn`
/// (`<api>:*` and `*` cover it). The nonce is not consumed: the cell's own gate checks the same Hello next.
#[cfg(all(feature = "door", unix))]
pub fn spawn_gate(self_id: NodeId) -> ce_wire::SpawnGate {
    Arc::new(move |h: &Hello| {
        // an instance Hello (`obs.source#wx.metar`) is rooted and granted as its api: `obs.source:spawn`
        let api = ce_wire::base_api(&h.api);
        let roots = mesh_roots_for(api);
        let t = open_token(h)?;
        let now = now_ms();
        if now.abs_diff(t.unix_ms()) > MAX_SKEW_MS {
            return Err("hello clock skew".into());
        }
        let need = format!("{api}:spawn");
        match t {
            Token::V1(_) if v2_only(api) => Err(format!("{api} takes hash-id (v2) caps only")),
            Token::V1(p) => {
                let chain = decode_chain_bytes(&p.chain).map_err(|e| format!("chain: {e}"))?;
                authorize(&self_id, &roots, &[], now / 1000, &p.requester, &need, &chain, &|_, _| false)
            }
            // The door does not link the cell's api: the cap must match the Hello's schema (which the requester
            // signed); the cell's own gate then checks that schema against the one it serves.
            Token::V2(p) => {
                let s = cap_hash::Serving { self_id: &self_id, tags: &[], api, hello_api: &h.api, schemas: &[h.schema], cell: None };
                let leaf = cap_hash::verify_chain(&s, &roots, now / 1000, &p.requester, &p.chain, &|_, _| false)?;
                leaf.ops.iter().any(|o| ability_covers(o, &need)).then_some(()).ok_or_else(|| format!("capability does not grant '{need}'"))
            }
        }
    })
}

/// A short-lived chain this node signs for itself: `abilities` for `secs` seconds. Every door and cell that accepts
/// this node as a root (every net.mesh peer does) honours it.
pub fn self_chain(id: &Identity, abilities: Vec<String>, secs: u64) -> Vec<SignedCapability> {
    self_chain_in(id, abilities, secs, None)
}

/// [`self_chain`] confined to paths under `path_prefix` (a `ce-cap` caveat; the cell that reads files enforces it).
pub fn self_chain_in(id: &Identity, abilities: Vec<String>, secs: u64, path_prefix: Option<String>) -> Vec<SignedCapability> {
    let now = now_ms() / 1000;
    let mut n = [0u8; 8];
    getrandom::getrandom(&mut n).expect("os random");
    let caveats = ce_cap::Caveats { not_after: now + secs, path_prefix, ..Default::default() };
    vec![SignedCapability::issue(id, id.node_id(), abilities, ce_cap::Resource::Any, caveats, u64::from_le_bytes(n), None)]
}

/// The node ids of the net.mesh peers (`ce_wire::mesh_peer_ids`, the door refreshes the file every 60 s), plus the
/// How often a mesh gate re-reads the peers and roots files (two small reads); `$CE_GATE_ROOTS_EVERY_MS` overrides it.
pub const MESH_ROOTS_EVERY: std::time::Duration = std::time::Duration::from_secs(30);
/// How often a refusal for an unknown root may re-read the peers and roots files (a stranger costs one small file read
/// a second at most; a node that just joined is rooted on its first call).
pub const ROOTS_ON_REFUSAL_EVERY: std::time::Duration = std::time::Duration::from_secs(1);

/// Every net.mesh peer's id plus the unscoped lines of `~/.config/ce-wire/roots`: the authorities for any api.
pub fn mesh_roots() -> Vec<NodeId> {
    roots_from(None)
}

/// [`mesh_roots`] plus the roots lines scoped to `api`. A roots line is `<64 hex id> [api,api,...]` (`#` comments):
/// a machine whose ce key differs from its net.mesh key, or one trusted for only some cells (e.g. two
/// machines that root each other for two named cells only).
pub fn mesh_roots_for(api: &str) -> Vec<NodeId> {
    roots_from(Some(api))
}

/// Cells whose rights are secrets or code (with mesh-wide roots one taken machine reads
/// every key and installs on every other): no net.mesh peer and no bare roots line roots them, only this node's key and
/// the roots lines that name the api. More apis: one per line in `~/.config/ce-wire/own-key`.
pub const OWN_KEY_ONLY: &[&str] = &["keys", "cell.install"];

/// True when `api` is rooted by this node's key and the roots lines naming it only ([`OWN_KEY_ONLY`] or the own-key file).
pub fn own_key_only(api: &str) -> bool {
    OWN_KEY_ONLY.contains(&api)
        || std::fs::read_to_string(ce_wire::peers_file().with_file_name("own-key"))
            .unwrap_or_default()
            .lines()
            .any(|l| l.split('#').next().unwrap_or("").trim() == api)
}

fn roots_from(api: Option<&str>) -> Vec<NodeId> {
    let own = api.is_some_and(own_key_only);
    let extra = std::fs::read_to_string(ce_wire::peers_file().with_file_name("roots")).unwrap_or_default();
    let file = extra.lines().filter_map(|l| {
        let mut w = l.split('#').next().unwrap_or("").split_whitespace();
        let id = w.next()?.to_string();
        match w.next() {
            None => (!own).then_some(id),
            Some(apis) => api.filter(|a| apis.split(',').any(|x| x.trim() == *a)).map(|_| id),
        }
    });
    ce_wire::mesh_peer_ids()
        .into_iter()
        .filter_map(|(_, id)| id)
        .filter(|_| !own)
        .chain(file)
        .filter_map(|id| {
            (id.len() == 64).then_some(())?;
            let mut o = [0u8; 32];
            for i in 0..32 {
                o[i] = u8::from_str_radix(&id[2 * i..2 * i + 2], 16).ok()?;
            }
            Some(o)
        })
        .collect()
}

/// Another principal's key and grant in place of this node's (a boxed agent
/// or service): `$CE_AS` = its data dir (`identity/node.key` + ce-iam `wallet.toml`), `$CE_GRANT` =
/// the wallet label of the grant to present (`ops:<name>`). None when either is unset. A set pair that does not resolve
/// is an error, never a quiet fall back to this node's key: a boxed principal must not end up calling as the machine.
pub fn granted() -> std::io::Result<Option<(Identity, Vec<SignedCapability>)>> {
    let (Some(dir), Some(label)) = (std::env::var_os("CE_AS").filter(|v| !v.is_empty()), std::env::var("CE_GRANT").ok().filter(|v| !v.is_empty())) else {
        return Ok(None);
    };
    let dir = PathBuf::from(dir);
    let bad = |m: String| std::io::Error::other(format!("CE_AS/CE_GRANT: {m}"));
    if !dir.join("identity/node.key").is_file() {
        return Err(bad(format!("no identity/node.key under {}", dir.display())));
    }
    let id = Identity::load_or_generate(&dir.join("identity")).map_err(|e| bad(e.to_string()))?;
    let w = std::fs::read_to_string(dir.join("wallet.toml")).map_err(|e| bad(format!("{}: {e}", dir.join("wallet.toml").display())))?;
    let hex = wallet_cap(&w, &label).ok_or_else(|| bad(format!("no grant {label} in {}", dir.join("wallet.toml").display())))?;
    Ok(Some((id, chain_from_hex(&hex).map_err(bad)?)))
}

/// The `cap` hex of entry `label` in a ce-iam wallet.toml (`[entries."<label>"]` then `cap = "<hex>"`).
pub fn wallet_cap(toml: &str, label: &str) -> Option<String> {
    let head = format!("[entries.\"{label}\"]");
    let mut inside = false;
    for l in toml.lines().map(str::trim) {
        if l.starts_with('[') {
            inside = l == head;
        } else if inside {
            if let Some((k, v)) = l.split_once('=') {
                if k.trim() == "cap" {
                    return Some(v.trim().trim_matches('"').to_string()).filter(|h| !h.is_empty());
                }
            }
        }
    }
    None
}

/// The Hello token a fleet machine uses for its own calls to cell `A`: this node's key signs itself `<api>:*` for
/// `secs` seconds. Accepted by every cell and door that roots this node (every net.mesh peer and `roots` entry).
/// With `$CE_GATE_CAP_V2=1` the token is v2 ([`self_proof2`]); only cells built with v2 support read it.
///
/// The first call also turns on this process's provider-proof check ([`provider::enable_auto`]): env or node file.
pub fn self_proof<A: Api>(secs: u64) -> std::io::Result<Vec<u8>> {
    provider::enable_auto();
    if let Some((id, chain)) = granted()? {
        return Ok(proof::<A>(&id, &chain));
    }
    if emit_v2() {
        return self_proof2::<A>(secs);
    }
    let me = node_identity()?;
    Ok(proof::<A>(&me, &self_chain(&me, vec![format!("{}:*", A::NAME)], secs)))
}

/// [`self_proof`] for instance `name` of `A` (`Client::by_instance`).
pub fn self_proof_as<A: Api>(name: &str, secs: u64) -> std::io::Result<Vec<u8>> {
    provider::enable_auto();
    if let Some((id, chain)) = granted()? {
        return Ok(proof_as::<A>(&id, &chain, name));
    }
    let me = node_identity()?;
    if emit_v2() {
        return Ok(proof2_as::<A>(&me, &[self_cap2::<A>(&me, secs)], name));
    }
    Ok(proof_as::<A>(&me, &self_chain(&me, vec![format!("{}:*", A::NAME)], secs), name))
}

fn emit_v2() -> bool {
    std::env::var("CE_GATE_CAP_V2").is_ok_and(|v| v == "1")
}

/// A hash-id cap this node signs for itself: every op of `A` at `A::SCHEMA`, valid from now for `secs` seconds.
pub fn self_cap2<A: Api>(id: &Identity, secs: u64) -> cap_hash::Cap {
    let now = now_ms() / 1000;
    let cv = ce_cap::Caveats { not_before: now.saturating_sub(MAX_SKEW_MS / 1000), not_after: now + secs, ..Default::default() };
    cap_hash::Cap::root(id, id.node_id(), A::NAME, A::SCHEMA, vec!["*".into()], cv)
}

/// The v2 [`self_proof`]: a [`self_cap2`] in a [`proof2`].
pub fn self_proof2<A: Api>(secs: u64) -> std::io::Result<Vec<u8>> {
    provider::enable_auto();
    let me = node_identity()?;
    Ok(proof2::<A>(&me, &[self_cap2::<A>(&me, secs)]))
}

/// Let `by_name` ask net.find (`ce_wire::find`) with this node's self proof (`net.find:*`), so a stopped cell is found
/// or started on the mesh. Call once at start; without it the finder gets an empty token.
pub fn enable_find() {
    ce_wire::find::set_mesh_token(|| self_proof::<ce_wire::find::NetFind>(60).unwrap_or_default());
}
