//! Provider proof: without it anyone could pretend to provide someone else's capability, so the
//! provider proves it with its key and a hash-id capability.
//!
//! The caller's side of ce-cap v2 proves who may CALL a cell. This module carries the other direction: the cell that
//! answers a Hello proves it may SERVE that api at that schema. ce-wire only moves bytes; what the proof is and how it
//! is checked lives in ce-gate (`ce_gate::provider`), which installs the two hooks here.
//!
//! On the wire, behind an opt-in, nothing changes for anyone who has not opted in:
//! - client: when a verifier is installed ([`set_verifier`]), the Hello payload gets one more value after its
//!   `OpTable`: a [`ProviderAsk`] (magic + 32-byte random nonce). An older server reads Hello | HelloExt | OpTable and
//!   ignores what follows (postcard `from_bytes` stops at the end of the value), so it answers as before.
//! - server: when a prover is installed ([`set_prover`]) and the Hello carries an ask, the `Ok` answer gets one more
//!   value after its `OpTable`: a [`ProviderAnswer`] (magic + opaque proof bytes from the prover). An older client
//!   ignores it the same way.
//! - client: the verifier is given the ask, the Hello it sent and the answer's proof bytes (None when the server sent
//!   none). Its `Err` closes the connection with `Refusal::Gate("provider: ...")` before any op is sent.
//!
//! With no verifier installed the Hello bytes are exactly what they were before this module existed (tested in
//! `tests::off_by_default_changes_no_byte`).
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

/// First bytes of a [`ProviderAsk`] / [`ProviderAnswer`]: a trailing value without them is not read as one.
pub const ASK_MAGIC: [u8; 8] = *b"cesrvq1\0";
pub const ANSWER_MAGIC: [u8; 8] = *b"cesrva1\0";

/// Client -> server, after the Hello's OpTable: "prove you may serve what I asked for, over this nonce".
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderAsk {
    pub magic: [u8; 8],
    pub nonce: [u8; 32],
}

/// Server -> client, after the Ok answer's OpTable: the prover's bytes (ce-gate: a postcard `ServeProof`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ProviderAnswer {
    pub magic: [u8; 8],
    pub proof: Vec<u8>,
}

/// What a prover or verifier sees of one connection.
pub struct Ctx<'a> {
    /// The Hello's api: `A::NAME` or `<A::NAME>#<instance>`.
    pub hello_api: &'a str,
    /// The Hello's schema hash (the caller's `A::SCHEMA`, or the adapted older one).
    pub schema: u64,
    /// The Hello's token bytes: the proof signs their hash, so one proof answers one Hello only.
    pub token: &'a [u8],
    pub ask: &'a ProviderAsk,
    /// The far end's address when the client knows it (TCP). None over a stream (`connect_stream`).
    pub peer: Option<std::net::SocketAddr>,
}

pub type Prover = Arc<dyn Fn(&Ctx) -> Option<Vec<u8>> + Send + Sync>;
pub type Verifier = Arc<dyn Fn(&Ctx, Option<&[u8]>) -> Result<(), String> + Send + Sync>;

static PROVER: RwLock<Option<Prover>> = RwLock::new(None);
static VERIFIER: RwLock<Option<Verifier>> = RwLock::new(None);

/// Server: answer provider asks with `f` (None = send no proof; a verifying client then refuses this server).
pub fn set_prover(f: impl Fn(&Ctx) -> Option<Vec<u8>> + Send + Sync + 'static) {
    *PROVER.write().unwrap() = Some(Arc::new(f));
}

/// Client: ask every server for a provider proof and refuse it unless `f` accepts. Off until this is called.
pub fn set_verifier(f: impl Fn(&Ctx, Option<&[u8]>) -> Result<(), String> + Send + Sync + 'static) {
    *VERIFIER.write().unwrap() = Some(Arc::new(f));
}

/// Remove both hooks (tests; a process turning the check off again).
pub fn clear() {
    *PROVER.write().unwrap() = None;
    *VERIFIER.write().unwrap() = None;
}

pub fn verifier() -> Option<Verifier> {
    VERIFIER.read().unwrap().clone()
}

pub fn prover() -> Option<Prover> {
    PROVER.read().unwrap().clone()
}

/// A fresh ask (32 bytes from the OS).
pub fn new_ask() -> ProviderAsk {
    let mut nonce = [0u8; 32];
    fill_random(&mut nonce);
    ProviderAsk { magic: ASK_MAGIC, nonce }
}

fn fill_random(b: &mut [u8]) {
    // No getrandom dependency in ce-wire: /dev/urandom on unix; elsewhere std's per-process random hasher keys.
    use std::io::Read;
    if std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(b)).is_ok() {
        return;
    }
    use std::hash::{BuildHasher, Hasher};
    for c in b.chunks_mut(8) {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
        c.copy_from_slice(&h.finish().to_le_bytes()[..c.len()]);
    }
}

/// The Hello payload with `ask` appended (after Hello | HelloExt | OpTable).
pub fn append_ask(payload: &mut Vec<u8>, ask: &ProviderAsk) {
    payload.extend(postcard::to_stdvec(ask).expect("postcard to vec"));
}

/// The [`ProviderAsk`] after a wire-3 Hello's OpTable, if there is one.
pub fn ask_in_hello(p: &[u8]) -> Option<ProviderAsk> {
    let (_, rest) = postcard::take_from_bytes::<crate::Hello>(p).ok()?;
    let (ext, rest) = postcard::take_from_bytes::<crate::HelloExt>(rest).ok()?;
    if ext.wire < 3 {
        return None;
    }
    let (_, rest) = postcard::take_from_bytes::<crate::OpTable>(rest).ok()?;
    postcard::from_bytes::<ProviderAsk>(rest).ok().filter(|a| a.magic == ASK_MAGIC)
}

/// The `Ok` answer for a wire-3 caller, with the prover's answer to `ask` appended when there is a prover and an ask.
pub fn ok_payload_proved(session: u64, wire: u32, ops: &[(u32, u64)], hello: &crate::Hello, ask: Option<&ProviderAsk>) -> Vec<u8> {
    let mut p = crate::ok_payload(session, wire, ops);
    if wire < 3 {
        return p;
    }
    if let (Some(ask), Some(pr)) = (ask, prover()) {
        let ctx = Ctx { hello_api: &hello.api, schema: hello.schema, token: &hello.token, ask, peer: None };
        if let Some(proof) = pr(&ctx) {
            p.extend(postcard::to_stdvec(&ProviderAnswer { magic: ANSWER_MAGIC, proof }).expect("postcard to vec"));
        }
    }
    p
}

/// The `Ok` answer to the Hello in `hello_buf` (both servers, tokio and blocking), with a provider proof when the
/// caller asked and a prover is installed. Without a prover, or without an ask, it is `ok_payload` unchanged.
pub fn ok_answer_for<A: crate::Api>(hello_buf: &[u8], key: u64, wire: u32) -> Vec<u8> {
    let ops = crate::op_hashes::<A>();
    if prover().is_none() {
        return crate::ok_payload(key, wire, &ops);
    }
    let ask = ask_in_hello(hello_buf);
    match (ask, postcard::take_from_bytes::<crate::Hello>(hello_buf)) {
        (Some(ask), Ok((h, _))) => ok_payload_proved(key, wire, &ops, &h, Some(&ask)),
        _ => crate::ok_payload(key, wire, &ops),
    }
}

/// The proof bytes after an `Ok` answer's OpTable, if the server sent any.
pub fn proof_in_answer(p: &[u8]) -> Option<Vec<u8>> {
    let (r, rest) = postcard::take_from_bytes::<crate::Refusal>(p).ok()?;
    if !matches!(r, crate::Refusal::Ok { .. }) {
        return None;
    }
    let (_, rest) = postcard::take_from_bytes::<crate::OpTable>(rest).ok()?;
    postcard::from_bytes::<ProviderAnswer>(rest).ok().filter(|a| a.magic == ANSWER_MAGIC).map(|a| a.proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{hello_payload_ops, split_answer, split_hello_ops, Hello};

    fn hello() -> Hello {
        Hello { api: "x.y".into(), version: 1, schema: 7, token: vec![1, 2, 3], spawn: false }
    }

    #[test]
    fn off_by_default_changes_no_byte() {
        // the payload a client builds with no verifier is hello_payload_ops' alone; nothing here appends to it
        let p = hello_payload_ops(&hello(), std::time::Duration::from_secs(5), &[(1, 2)]).unwrap();
        assert_eq!(ask_in_hello(&p), None);
        assert_eq!(proof_in_answer(&crate::ok_payload(9, 3, &[(1, 2)])), None);
    }

    #[test]
    fn an_older_peer_reads_past_the_ask_and_the_answer() {
        let mut p = hello_payload_ops(&hello(), std::time::Duration::from_secs(5), &[(1, 2)]).unwrap();
        let ask = new_ask();
        append_ask(&mut p, &ask);
        let (h, ext, ops) = split_hello_ops(&p).unwrap();
        assert_eq!((h.api.as_str(), ext.wire, ops), ("x.y", 3, vec![(1, 2)]));
        assert_eq!(ask_in_hello(&p), Some(ask));
        let mut a = crate::ok_payload(9, 3, &[(1, 2)]);
        a.extend(postcard::to_stdvec(&ProviderAnswer { magic: ANSWER_MAGIC, proof: vec![5; 40] }).unwrap());
        let (r, ops) = split_answer(&a).unwrap();
        assert_eq!((r, ops), (crate::Refusal::Ok { session: 9 }, vec![(1, 2)]));
        assert_eq!(proof_in_answer(&a), Some(vec![5; 40]));
    }

    #[test]
    fn two_asks_differ() {
        assert_ne!(new_ask().nonce, new_ask().nonce);
    }
}
