//! Provider proof: the serving side of cap v2: a capability can be
//! provided by a cell, so a provider must prove with its key and a hash-id capability that it may serve, or anyone
//! could pretend to provide someone else's capability.
//!
//! A **serve cap** is an ordinary cap v2 ([`cap_hash::Cap`]) whose ops are exactly [`SERVE`]: issuer R lets node X
//! serve api A at schema S (optionally one cell build). A provider answers a client's [`ce_wire::provider::ProviderAsk`]
//! with a [`ServeProof`]: its serve chain plus its node key's signature over [`signed_bytes`] (the client's nonce, the
//! Hello's api and schema, the sha256 of the Hello token, the provider key, the cell id and the chain's ids). The
//! client checks it with [`verify_serve`] and refuses the connection otherwise.
//!
//! Serve authority is NOT caller authority: serve roots are this node's own key plus `~/.config/ce-wire/serve-roots`
//! (`<64 hex id> [api,api,...]`), never every net.mesh peer. A provider can never root its own serve chain unless a
//! client lists it as a serve root.
use crate::cap_hash::{self, Cap, CapHash, Serving};
use ce_cap::{Caveats, Resource};
use ce_identity::{Identity, NodeId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The one op a serve cap carries. `@` is never in an op name, so no caller right is ever "serve"; and every link of a
/// serve chain must list it literally (a caller cap with `*` does not cover it, see [`verify_serve`]).
pub const SERVE: &str = "@serve";
const DOMAIN: &str = "ce-provider-proof-v1";

/// The provider's answer to an ask.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ServeProof {
    /// The provider's node key (the serve chain's leaf subject).
    pub provider: NodeId,
    /// The provider's [`cap_hash::cell_id`], when it knows its build; a cell-pinned serve chain needs it.
    pub cell: Option<CapHash>,
    /// Root first.
    pub chain: Vec<Cap>,
    /// ed25519 by `provider` over [`signed_bytes`].
    pub sig: Vec<u8>,
}

#[derive(Serialize)]
struct Signed<'a> {
    domain: &'a str,
    hello_api: &'a str,
    schema: u64,
    nonce: [u8; 32],
    token_hash: [u8; 32],
    provider: NodeId,
    cell: Option<CapHash>,
    ids: Vec<CapHash>,
}

/// The bytes a provider signs: postcard of (domain "ce-provider-proof-v1", hello_api, schema, client nonce,
/// sha256(Hello token), provider key, cell id, the chain's cap ids). Each cap id commits to its whole body.
pub fn signed_bytes(hello_api: &str, schema: u64, nonce: &[u8; 32], token: &[u8], provider: &NodeId, cell: Option<CapHash>, chain: &[Cap]) -> Vec<u8> {
    let token_hash: [u8; 32] = Sha256::digest(token).into();
    let ids = chain.iter().map(|c| c.id).collect();
    postcard::to_stdvec(&Signed { domain: DOMAIN, hello_api, schema, nonce: *nonce, token_hash, provider: *provider, cell, ids }).expect("postcard to vec")
}

/// A root serve cap: `issuer` lets `provider` serve `api` at `schema` (and only build `cell`, when given) during
/// `caveats`' window. `resource` is the provider node itself.
pub fn serve_cap(issuer: &Identity, provider: NodeId, api: &str, schema: u64, cell: Option<CapHash>, caveats: Caveats) -> Cap {
    let body = cap_hash::CapBody {
        v: 2,
        issuer: issuer.node_id(),
        subject: provider,
        api: api.into(),
        schema,
        cell,
        ops: vec![SERVE.into()],
        resource: Resource::Node(provider),
        caveats,
        nonce: cap_hash::random_nonce(),
        parent: None,
    };
    Cap::sign(issuer, body).expect("own body")
}

/// The provider's proof for one ask.
pub fn prove(me: &Identity, chain: &[Cap], cell: Option<CapHash>, hello_api: &str, schema: u64, nonce: &[u8; 32], token: &[u8]) -> ServeProof {
    let provider = me.node_id();
    let sig = me.sign(&signed_bytes(hello_api, schema, nonce, token, &provider, cell, chain)).to_vec();
    ServeProof { provider, cell, chain: chain.to_vec(), sig }
}

/// What the client asked for and where it dialled.
pub struct Asked<'a> {
    pub hello_api: &'a str,
    pub schema: u64,
    pub nonce: &'a [u8; 32],
    pub token: &'a [u8],
    /// The node key the client expects at the address it dialled (loopback = its own key, a mesh ip = that peer's key
    /// from the peers file). None = unknown: the proof is checked, the address is not bound (docs: "binding").
    pub expect: Option<NodeId>,
}

/// Check a provider's answer. Refused when: no proof; it does not decode; the provider is not the node expected at the
/// dialled address; the signature is not the provider's over this ask; the chain is empty, does not root at a serve
/// root (the provider's own key is not one unless listed), or any link does not list [`SERVE`] literally; or
/// [`cap_hash::verify_chain`] refuses it as a chain for this api, this schema and this cell, held by the provider.
/// Returns the provider's key. Cost: 1 + chain length ed25519 verifies and 2 + chain length sha256s.
pub fn verify_serve(roots: &[NodeId], now_s: u64, a: &Asked, proof: Option<&[u8]>, is_revoked: &dyn Fn(&NodeId, u64) -> bool) -> Result<NodeId, String> {
    let bytes = proof.ok_or("server presented no serve proof")?;
    let p: ServeProof = postcard::from_bytes(bytes).map_err(|e| format!("serve proof does not decode: {e}"))?;
    if let Some(e) = a.expect {
        if e != p.provider {
            return Err(format!("provider key {} is not the node at the dialled address ({})", short(&p.provider), short(&e)));
        }
    }
    let sig: [u8; 64] = p.sig.as_slice().try_into().map_err(|_| "serve proof signature is not 64 bytes".to_string())?;
    ce_identity::verify(&p.provider, &signed_bytes(a.hello_api, a.schema, a.nonce, a.token, &p.provider, p.cell, &p.chain), &sig)
        .map_err(|_| "serve proof is not signed by the provider over this ask".to_string())?;
    let first = p.chain.first().ok_or("serve proof has no chain")?;
    if !roots.contains(&first.body.issuer) {
        return Err(format!("serve chain roots at {}, not a serve root of this client", short(&first.body.issuer)));
    }
    if let Some(i) = p.chain.iter().position(|c| !c.body.ops.iter().any(|o| o == SERVE)) {
        return Err(format!("link {i}: not a serve cap (ops do not list {SERVE})"));
    }
    let base = ce_wire::base_api(a.hello_api);
    let schemas = [a.schema];
    let s = Serving { self_id: &p.provider, tags: &[], api: base, hello_api: a.hello_api, schemas: &schemas, cell: p.cell };
    cap_hash::verify_chain(&s, roots, now_s, &p.provider, &p.chain, is_revoked).map_err(|e| format!("serve chain: {e}"))?;
    Ok(p.provider)
}

fn short(id: &NodeId) -> String {
    id[..4].iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_id(h: &str) -> Option<NodeId> {
    (h.len() == 64).then_some(())?;
    let mut o = [0u8; 32];
    for i in 0..32 {
        o[i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(o)
}

/// This client's serve roots for `api`: its own node key plus each `serve-roots` line that is bare or names `api`.
pub fn serve_roots_for(own: NodeId, api: &str) -> Vec<NodeId> {
    let f = std::fs::read_to_string(ce_wire::peers_file().with_file_name("serve-roots")).unwrap_or_default();
    std::iter::once(own)
        .chain(f.lines().filter_map(|l| {
            let mut w = l.split('#').next().unwrap_or("").split_whitespace();
            let id = parse_id(w.next()?)?;
            match w.next() {
                None => Some(id),
                Some(apis) => apis.split(',').any(|x| x.trim() == api).then_some(id),
            }
        }))
        .collect()
}

/// The node key a client expects at `peer`: its own on loopback, the peers file's key for a mesh ip, else None.
pub fn expected_at(own: NodeId, peer: Option<std::net::SocketAddr>) -> Option<NodeId> {
    let ip = peer?.ip();
    if ip.is_loopback() {
        return Some(own);
    }
    ce_wire::mesh_peer_ids().into_iter().find(|(i, _)| *i == ip).and_then(|(_, id)| parse_id(&id?))
}

/// Install the client check in ce-wire: every Hello from this process asks for a serve proof and a connection without
/// a valid one is refused. Roots: [`serve_roots_for`]; revocations: the node's `revocations.json`.
pub fn enable_verifier() -> std::io::Result<()> {
    enable_verifier_mode(Mode::Strict)
}

/// How a verifying client treats a provider without a good proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Refuse the connection.
    Strict,
    /// Log the refusal (stderr and `<ce dir>/provider-proof.log`) and let the call through, except for the apis
    /// listed here (exact, or `prefix.*`), which are refused. Lead 2026-10-22: report-only for 7 days, then strict
    /// for `keys`, `cell.install`, `storage.*`.
    Report { strict: Vec<String> },
}

impl Mode {
    /// `CE_PROVIDER_PROOF`: `1` or `strict` = [`Mode::Strict`]; `report` = [`Mode::Report`] with the apis in
    /// `CE_PROVIDER_PROOF_STRICT` (comma separated) refused; anything else, or unset, = off.
    pub fn from_env() -> Option<Mode> {
        match std::env::var("CE_PROVIDER_PROOF").ok()?.as_str() {
            "1" | "strict" => Some(Mode::Strict),
            "report" => Some(Mode::Report {
                strict: std::env::var("CE_PROVIDER_PROOF_STRICT")
                    .unwrap_or_default()
                    .split(',')
                    .map(|a| a.trim().to_string())
                    .filter(|a| !a.is_empty())
                    .collect(),
            }),
            _ => None,
        }
    }

    /// [`Mode::from_env`] when `CE_PROVIDER_PROOF` is set; else the node file `~/.config/ce-wire/provider-proof`:
    /// `report [api,prefix.*,...]` (the list is refused, as `CE_PROVIDER_PROOF_STRICT`), `strict`, or `off`. No file
    /// = off. One file per machine turns the check on for every process built with [`enable_auto`].
    pub fn from_node() -> Option<Mode> {
        if std::env::var_os("CE_PROVIDER_PROOF").is_some() {
            return Mode::from_env();
        }
        Mode::parse(&std::fs::read_to_string(ce_wire::peers_file().with_file_name("provider-proof")).ok()?)
    }

    /// The node file's text (see [`Mode::from_node`]); `#` starts a comment.
    pub fn parse(text: &str) -> Option<Mode> {
        let mut w = text.lines().map(|l| l.split('#').next().unwrap_or("")).flat_map(str::split_whitespace);
        match w.next()? {
            "strict" | "1" => Some(Mode::Strict),
            "report" => Some(Mode::Report { strict: w.flat_map(|x| x.split(',')).map(str::trim).filter(|a| !a.is_empty()).map(String::from).collect() }),
            _ => None,
        }
    }

    /// Whether a failed proof for `api` (a base api) refuses the connection.
    pub fn refuses(&self, api: &str) -> bool {
        match self {
            Mode::Strict => true,
            Mode::Report { strict } => strict.iter().any(|s| match s.strip_suffix(".*") {
                Some(pre) => api == pre || api.strip_prefix(pre).is_some_and(|r| r.starts_with('.')),
                None => api == s,
            }),
        }
    }
}

/// Seconds between two report lines for the same (result, api, peer); each line carries the count since the last one.
pub const REPORT_EVERY_S: u64 = 3600;

/// [`enable_verifier`] in a [`Mode`]. In report mode each check is counted and logged to `<ce dir>/provider-proof.log`
/// at most once per [`REPORT_EVERY_S`] per (result, api, peer ip): `<unix s> ok <api> <peer> n=<checks> <provider>`,
/// `<unix s> would-refuse <api> <peer> n=<checks> <why>` (the call goes on) or `refused` (the api is listed strict).
pub fn enable_verifier_mode(mode: Mode) -> std::io::Result<()> {
    let own = crate::node_identity()?.node_id();
    let rv = std::sync::Mutex::new(crate::Revocations { path: crate::ce_dir().join("revocations.json"), mtime: None, set: Default::default() });
    let log = crate::ce_dir().join("provider-proof.log");
    let seen: std::sync::Mutex<std::collections::HashMap<(&'static str, String, String), (u64, u64)>> = Default::default();
    let report = matches!(mode, Mode::Report { .. });
    ce_wire::provider::set_verifier(move |c, proof| {
        let base = ce_wire::base_api(c.hello_api);
        let roots = serve_roots_for(own, base);
        let mut rv = rv.lock().unwrap();
        rv.refresh();
        let revoked = |i: &NodeId, n: u64| rv.set.contains(&(*i, n));
        let a = Asked { hello_api: c.hello_api, schema: c.schema, nonce: &c.ask.nonce, token: c.token, expect: expected_at(own, c.peer) };
        let now = crate::now_ms() / 1000;
        let r = verify_serve(&roots, now, &a, proof, &revoked);
        if report {
            let peer = c.peer.map_or("-".to_string(), |p| p.ip().to_string());
            let mut seen = seen.lock().unwrap();
            let kind = match &r { Ok(_) => "ok", Err(_) if mode.refuses(base) => "refused", Err(_) => "would-refuse" };
            let e = seen.entry((kind, c.hello_api.to_string(), peer.clone())).or_insert((0, 0));
            e.1 += 1;
            if e.0 == 0 || now >= e.0 + REPORT_EVERY_S {
                let what = match &r { Ok(p) => format!("ok {} {peer} n={} {}", c.hello_api, e.1, short(p)), Err(why) => format!("{kind} {} {peer} n={} {why}", c.hello_api, e.1) };
                *e = (now, 0);
                let line = format!("{now} {what}\n");
                if r.is_err() {
                    eprint!("provider-proof: {line}");
                }
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&log) {
                    let _ = f.write_all(line.as_bytes());
                }
            }
        }
        match r {
            Err(_) if !mode.refuses(base) => Ok(()),
            r => r.map(|_| ()),
        }
    });
    Ok(())
}

/// Install the server answer in ce-wire: asks for an api this node holds a serve chain for (at that schema) are
/// answered with a [`ServeProof`]; others get none (and a verifying client refuses).
pub fn enable_prover(me: Identity, chains: Vec<Vec<Cap>>, cell: Option<CapHash>) {
    ce_wire::provider::set_prover(move |c| {
        let base = ce_wire::base_api(c.hello_api);
        let chain = chains.iter().find(|ch| ch.first().is_some_and(|f| (f.body.api == base || f.body.api == c.hello_api) && f.body.schema == c.schema))?;
        Some(postcard::to_stdvec(&prove(&me, chain, cell, c.hello_api, c.schema, &c.ask.nonce, c.token)).expect("postcard to vec"))
    });
}

/// Once per process: [`enable_verifier_mode`] with [`Mode::from_node`] (env, else the node file), so every client that
/// signs its Hello with [`crate::self_proof`] checks its providers without a code change. Off = nothing installed.
/// Rollout: report first, count the lines per door for 48 h, strict only on a clean report.
pub fn enable_auto() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if let Some(m) = Mode::from_node() {
            if let Err(e) = enable_verifier_mode(m) {
                eprintln!("provider-proof: not on: {e}");
            }
        }
    });
}

/// `CE_PROVIDER_PROOF=1|strict|report` ([`Mode::from_env`]): [`enable_verifier_mode`] for this process. Off (the
/// default): nothing is installed and the wire bytes are what they were. A cell installs its prover with
/// [`enable_prover`] from its serve chain file.
pub fn enable_from_env() -> std::io::Result<bool> {
    match Mode::from_env() {
        Some(m) => enable_verifier_mode(m).map(|_| true),
        None => Ok(false),
    }
}
