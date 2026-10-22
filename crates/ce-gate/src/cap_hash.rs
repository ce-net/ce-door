//! Hash-id capabilities (cap v2): a capability has a hash id so it is identifiable,
//! and nobody can take a capability someone else created and fake it.
//!
//! A [`Cap`] is a [`CapBody`] plus its id and the issuer's signature:
//! - `id = sha256("ce-cap-v2\0" | postcard(body))` over issuer, subject, api, schema hash, optional cell id, ops,
//!   resource, caveats (not-before, expiry, path prefix, ...), nonce and the parent's id;
//! - `sig = ed25519(issuer, "ce-cap-v2-sig\0" | id)`.
//!
//! [`verify_chain`] refuses a link whose id does not recompute from its body (a re-labelled cap), whose signature is
//! not the issuer's over that id, whose api or schema hash is not the serving cell's, whose cell pin is not the serving
//! cell, or whose issuer did not hold the right it hands on (continuity + attenuation, like `ce_cap::authorize`).
//!
//! A cell's identity is [`cell_id`]: `sha256("ce-cell-id-v1\0" | postcard(api, schema, build rev, signer key))`.
use ce_cap::{ability_covers, Caveats, Resource};
use ce_identity::{Identity, NodeId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The content hash that names a capability (and a cell build).
pub type CapHash = [u8; 32];

pub const CAP_DOMAIN: &[u8] = b"ce-cap-v2\0";
const SIG_DOMAIN: &[u8] = b"ce-cap-v2-sig\0";
const CELL_DOMAIN: &[u8] = b"ce-cell-id-v1\0";
/// Longest chain a gate verifies (each link costs one ed25519 verify).
pub const MAX_CHAIN: usize = 16;
/// Most ops one link may list.
pub const MAX_OPS: usize = 64;

/// The signed statement: `issuer` lets `subject` call `ops` of `api` at schema `schema` on nodes matching `resource`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CapBody {
    /// Format version, always 2; a body of another version never hashes to a v2 id.
    pub v: u8,
    pub issuer: NodeId,
    pub subject: NodeId,
    /// The api name (`docs.read`), or one instance of it (`obs.source#wx.metar`).
    pub api: String,
    /// The api's schema hash (`Api::SCHEMA`): a cap for one schema never opens another.
    pub schema: u64,
    /// One cell build ([`cell_id`]); None = any build of this api and schema.
    pub cell: Option<CapHash>,
    /// Rights of this api (`docs.read:get`, `docs.read:*`, `*` = every right of this api only).
    pub ops: Vec<String>,
    pub resource: Resource,
    /// `not_before` / `not_after` (unix seconds) and the action caveats of `ce_cap`.
    pub caveats: Caveats,
    /// Issuer-chosen, random: names the cap in `revocations.json` as `(issuer, nonce)`.
    pub nonce: u64,
    /// The parent link's id; None = root (its issuer must be an accepted root).
    pub parent: Option<CapHash>,
}

/// A [`CapBody`], its id and the issuer's signature over the id.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Cap {
    pub body: CapBody,
    pub id: CapHash,
    pub sig: Vec<u8>,
}

/// The id of `body`: sha256 over the domain and the postcard bytes of every field.
pub fn cap_hash(body: &CapBody) -> CapHash {
    let mut h = Sha256::new();
    h.update(CAP_DOMAIN);
    h.update(postcard::to_stdvec(body).expect("postcard to vec"));
    h.finalize().into()
}

fn sig_bytes(id: &CapHash) -> Vec<u8> {
    [SIG_DOMAIN, id.as_slice()].concat()
}

/// A cell's identity: sha256 over api, schema hash, build rev and the key that signs for the build.
pub fn cell_id(api: &str, schema: u64, build_rev: &str, signer: &NodeId) -> CapHash {
    let mut h = Sha256::new();
    h.update(CELL_DOMAIN);
    h.update(postcard::to_stdvec(&(api, schema, build_rev, signer)).expect("postcard to vec"));
    h.finalize().into()
}

pub fn random_nonce() -> u64 {
    let mut n = [0u8; 8];
    getrandom::getrandom(&mut n).expect("os random");
    u64::from_le_bytes(n)
}

impl Cap {
    /// Sign `body` with `issuer`. Refused when `body.issuer` is not that key or the version is not 2.
    pub fn sign(issuer: &Identity, body: CapBody) -> Result<Cap, String> {
        if body.issuer != issuer.node_id() {
            return Err("cap issuer is not the signing key".into());
        }
        if body.v != 2 {
            return Err(format!("cap version {} is not 2", body.v));
        }
        let id = cap_hash(&body);
        let sig = issuer.sign(&sig_bytes(&id)).to_vec();
        Ok(Cap { body, id, sig })
    }

    /// A root cap: `issuer` gives `subject` `ops` of `api`/`schema` on any node, valid `[not_before, not_after]`.
    pub fn root(issuer: &Identity, subject: NodeId, api: &str, schema: u64, ops: Vec<String>, caveats: Caveats) -> Cap {
        let body = CapBody { v: 2, issuer: issuer.node_id(), subject, api: api.into(), schema, cell: None, ops, resource: Resource::Any, caveats, nonce: random_nonce(), parent: None };
        Cap::sign(issuer, body).expect("own body")
    }

    /// Hand a narrower cap on: `holder` (this cap's subject) gives `subject` `ops` under `caveats`. Api, schema, cell
    /// pin and resource are inherited.
    pub fn delegate(&self, holder: &Identity, subject: NodeId, ops: Vec<String>, caveats: Caveats) -> Result<Cap, String> {
        let b = &self.body;
        let body = CapBody { v: 2, issuer: holder.node_id(), subject, api: b.api.clone(), schema: b.schema, cell: b.cell, ops, resource: b.resource.clone(), caveats, nonce: random_nonce(), parent: Some(self.id) };
        Cap::sign(holder, body)
    }

    /// The id and signature check of one link, alone.
    pub fn verify_self(&self) -> Result<(), String> {
        if self.body.v != 2 {
            return Err(format!("cap version {} is not 2", self.body.v));
        }
        if cap_hash(&self.body) != self.id {
            return Err("cap id does not match its body".into());
        }
        let sig: [u8; 64] = self.sig.as_slice().try_into().map_err(|_| "cap signature is not 64 bytes".to_string())?;
        ce_identity::verify(&self.body.issuer, &sig_bytes(&self.id), &sig).map_err(|_| "cap signature is not the issuer's".to_string())
    }
}

/// What the serving cell is, for [`verify_chain`].
pub struct Serving<'a> {
    pub self_id: &'a NodeId,
    pub tags: &'a [String],
    /// The api the cell serves (`A::NAME`).
    pub api: &'a str,
    /// The name the Hello asked for (`A::NAME` or an instance key of it).
    pub hello_api: &'a str,
    /// `A::SCHEMA` and `A::ACCEPTS`: the schemas this cell answers.
    pub schemas: &'a [u64],
    /// This cell's [`cell_id`], when it knows its build; a cell-pinned cap is refused without it.
    pub cell: Option<CapHash>,
}

/// Verify a root-first v2 chain for `requester` at `now` (unix seconds) and return the leaf body. Refused when:
/// empty or longer than [`MAX_CHAIN`]; the root issuer is not this node or an accepted root; any link's id does not
/// recompute or its signature is not its issuer's over the id; a link's api is not the serving api (or the Hello's
/// instance), its schema not one this cell answers, or its cell pin not this cell; a link is not yet valid, expired,
/// revoked or for another node; a child is not issued by its parent's subject, does not name the parent's id, changes
/// api/schema/cell, or is broader than the parent (ops, resource, caveats); the leaf is not held by `requester`.
pub fn verify_chain<'c>(
    s: &Serving,
    roots: &[NodeId],
    now: u64,
    requester: &NodeId,
    chain: &'c [Cap],
    is_revoked: &dyn Fn(&NodeId, u64) -> bool,
) -> Result<&'c CapBody, String> {
    let (Some(first), Some(leaf)) = (chain.first(), chain.last()) else { return Err("no capability presented".into()) };
    if chain.len() > MAX_CHAIN {
        return Err(format!("capability chain longer than {MAX_CHAIN}"));
    }
    if &first.body.issuer != s.self_id && !roots.contains(&first.body.issuer) {
        return Err("capability chain does not root at an accepted authority".into());
    }
    for (i, link) in chain.iter().enumerate() {
        link.verify_self().map_err(|e| format!("link {i}: {e}"))?;
        let c = &link.body;
        if c.api != s.api && c.api != s.hello_api {
            return Err(format!("link {i}: cap is for api {}, not {}", c.api, s.hello_api));
        }
        if !s.schemas.contains(&c.schema) {
            return Err(format!("link {i}: cap is for schema {:016x}, this cell serves {:016x?}", c.schema, s.schemas));
        }
        if let Some(pin) = c.cell {
            if s.cell != Some(pin) {
                return Err(format!("link {i}: cap is pinned to another cell build"));
            }
        }
        if c.ops.len() > MAX_OPS {
            return Err(format!("link {i}: more than {MAX_OPS} ops"));
        }
        c.caveats.valid_at(now).map_err(|e| format!("link {i}: {e}"))?;
        if is_revoked(&c.issuer, c.nonce) {
            return Err(format!("link {i}: capability revoked"));
        }
        if !c.resource.matches(s.self_id, s.tags) {
            return Err(format!("link {i}: resource does not match this node"));
        }
        if i == 0 {
            if c.parent.is_some() {
                return Err("root capability must not name a parent".into());
            }
            continue;
        }
        let p = &chain[i - 1];
        if c.issuer != p.body.subject {
            return Err(format!("link {i}: issuer did not hold the parent cap"));
        }
        if c.parent != Some(p.id) {
            return Err(format!("link {i}: parent id does not match the chain"));
        }
        if c.api != p.body.api || c.schema != p.body.schema || (p.body.cell.is_some() && c.cell != p.body.cell) {
            return Err(format!("link {i}: api, schema or cell differs from the parent"));
        }
        if !c.ops.iter().all(|o| p.body.ops.iter().any(|po| ability_covers(po, o))) {
            return Err(format!("link {i}: ops exceed the parent"));
        }
        if !c.resource.is_subset_of(&p.body.resource) {
            return Err(format!("link {i}: resource is broader than the parent"));
        }
        if !c.caveats.is_narrower_or_equal(&p.body.caveats) {
            return Err(format!("link {i}: caveats are broader than the parent"));
        }
    }
    if &leaf.body.subject != requester {
        return Err("leaf capability is not held by the request sender".into());
    }
    Ok(&leaf.body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me(n: u8) -> Identity {
        Identity::from_secret_bytes(&[n; 32])
    }

    #[test]
    fn id_covers_every_field() {
        let a = me(1);
        let c = Cap::root(&a, me(2).node_id(), "x.y", 7, vec!["x.y:*".into()], Caveats::default());
        c.verify_self().unwrap();
        let mut variants = vec![];
        let mut b = c.body.clone();
        b.subject = me(3).node_id();
        variants.push(b);
        let mut b = c.body.clone();
        b.api = "x.z".into();
        variants.push(b);
        let mut b = c.body.clone();
        b.schema = 8;
        variants.push(b);
        let mut b = c.body.clone();
        b.ops.push("x.y:admin".into());
        variants.push(b);
        let mut b = c.body.clone();
        b.caveats.not_after = 1;
        variants.push(b);
        let mut b = c.body.clone();
        b.caveats.not_before = 1;
        variants.push(b);
        let mut b = c.body.clone();
        b.nonce ^= 1;
        variants.push(b);
        let mut b = c.body.clone();
        b.cell = Some([0; 32]);
        variants.push(b);
        for b in variants {
            assert_ne!(cap_hash(&b), c.id);
            // same id and sig, edited body: the id no longer recomputes
            assert_eq!(Cap { body: b.clone(), ..c.clone() }.verify_self().unwrap_err(), "cap id does not match its body");
            // edited body with its recomputed id: the issuer never signed that id
            let id = cap_hash(&b);
            assert!(Cap { body: b, id, sig: c.sig.clone() }.verify_self().unwrap_err().contains("not the issuer's"));
        }
    }

    #[test]
    fn cell_id_changes_with_each_input() {
        let k = me(1).node_id();
        let base = cell_id("a.b", 1, "rev1", &k);
        assert_ne!(base, cell_id("a.c", 1, "rev1", &k));
        assert_ne!(base, cell_id("a.b", 2, "rev1", &k));
        assert_ne!(base, cell_id("a.b", 1, "rev2", &k));
        assert_ne!(base, cell_id("a.b", 1, "rev1", &me(2).node_id()));
        assert_eq!(base, cell_id("a.b", 1, "rev1", &k));
    }

    #[test]
    fn sign_refuses_a_body_for_another_issuer() {
        let c = Cap::root(&me(1), me(2).node_id(), "x.y", 7, vec![], Caveats::default());
        assert!(Cap::sign(&me(3), c.body).is_err());
    }
}
