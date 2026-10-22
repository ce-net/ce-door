//! Provider proof: a node may answer for api A at schema S only with a serve chain rooted at
//! one of the client's serve roots and a signature by its own key over the client's nonce and Hello.
use ce_cap::Caveats;
use ce_gate::cap_hash::{self, Cap};
use ce_gate::provider::{self, prove, serve_cap, verify_serve, Asked, ServeProof, SERVE};
use ce_identity::Identity;
use ce_wire::{blocking, Refusal, WireError};

fn id(n: u8) -> Identity {
    Identity::from_secret_bytes(&[n; 32])
}

const API: &str = "storage.r2";
const SCHEMA: u64 = 0x1111_2222_3333_4444;
const NOW: u64 = 1_800_000_000;
const NONCE: [u8; 32] = [9; 32];
const TOKEN: &[u8] = b"the client's hello token";

fn window() -> Caveats {
    Caveats { not_before: NOW - 60, not_after: NOW + 3600, ..Default::default() }
}

fn asked(expect: Option<[u8; 32]>) -> Asked<'static> {
    Asked { hello_api: API, schema: SCHEMA, nonce: &NONCE, token: TOKEN, expect }
}

fn bytes(p: &ServeProof) -> Vec<u8> {
    postcard::to_stdvec(p).unwrap()
}

fn never(_: &[u8; 32], _: u64) -> bool {
    false
}

/// root = the authority the client trusts for serving; honest = a real provider; mallory = a mesh member with a valid
/// node key and no right to serve.
struct World {
    root: Identity,
    honest: Identity,
    mallory: Identity,
}

fn world() -> World {
    World { root: id(1), honest: id(2), mallory: id(3) }
}

fn check(w: &World, p: &ServeProof, expect: Option<[u8; 32]>) -> Result<[u8; 32], String> {
    verify_serve(&[w.root.node_id()], NOW, &asked(expect), Some(&bytes(p)), &never)
}

#[test]
fn good_provider_is_accepted() {
    let w = world();
    let chain = vec![serve_cap(&w.root, w.honest.node_id(), API, SCHEMA, None, window())];
    let p = prove(&w.honest, &chain, None, API, SCHEMA, &NONCE, TOKEN);
    assert_eq!(check(&w, &p, Some(w.honest.node_id())), Ok(w.honest.node_id()));
    assert_eq!(check(&w, &p, None), Ok(w.honest.node_id()));
}

#[test]
fn forged_provider_with_a_valid_key_and_no_serve_chain_is_refused() {
    let w = world();
    // signs correctly with its own key, presents no chain
    let p = prove(&w.mallory, &[], None, API, SCHEMA, &NONCE, TOKEN);
    assert!(check(&w, &p, None).unwrap_err().contains("no chain"));
    // roots its own serve cap: its key is not a serve root of this client
    let own = vec![serve_cap(&w.mallory, w.mallory.node_id(), API, SCHEMA, None, window())];
    let p = prove(&w.mallory, &own, None, API, SCHEMA, &NONCE, TOKEN);
    assert!(check(&w, &p, None).unwrap_err().contains("not a serve root"));
    // presents honest's real chain under its own key: the leaf is not held by it
    let stolen = vec![serve_cap(&w.root, w.honest.node_id(), API, SCHEMA, None, window())];
    let p = prove(&w.mallory, &stolen, None, API, SCHEMA, &NONCE, TOKEN);
    let e = check(&w, &p, None).unwrap_err();
    assert!(e.contains("resource does not match") || e.contains("not held"), "{e}");
    // no proof at all (an older or lying server)
    assert!(verify_serve(&[w.root.node_id()], NOW, &asked(None), None, &never).unwrap_err().contains("no serve proof"));
}

#[test]
fn chain_for_another_api_is_refused() {
    let w = world();
    let chain = vec![serve_cap(&w.root, w.mallory.node_id(), "docs.read", SCHEMA, None, window())];
    let p = prove(&w.mallory, &chain, None, API, SCHEMA, &NONCE, TOKEN);
    assert!(check(&w, &p, None).unwrap_err().contains("cap is for api docs.read"));
}

#[test]
fn chain_for_another_schema_is_refused() {
    let w = world();
    let chain = vec![serve_cap(&w.root, w.honest.node_id(), API, SCHEMA ^ 1, None, window())];
    let p = prove(&w.honest, &chain, None, API, SCHEMA, &NONCE, TOKEN);
    assert!(check(&w, &p, None).unwrap_err().contains("cap is for schema"));
}

#[test]
fn a_proof_answers_one_ask_only() {
    let w = world();
    let chain = vec![serve_cap(&w.root, w.honest.node_id(), API, SCHEMA, None, window())];
    // replayed to another nonce or another hello token: the signature no longer covers it
    let p = prove(&w.honest, &chain, None, API, SCHEMA, &[8; 32], TOKEN);
    assert!(check(&w, &p, None).unwrap_err().contains("not signed by the provider"));
    let p = prove(&w.honest, &chain, None, API, SCHEMA, &NONCE, b"another hello");
    assert!(check(&w, &p, None).unwrap_err().contains("not signed by the provider"));
    // the right provider at the wrong address (a relay that dialled honest for us)
    let p = prove(&w.honest, &chain, None, API, SCHEMA, &NONCE, TOKEN);
    assert!(check(&w, &p, Some(w.mallory.node_id())).unwrap_err().contains("not the node at the dialled address"));
}

#[test]
fn a_caller_cap_is_not_a_serve_cap() {
    let w = world();
    // root gave mallory every caller right of the api; mallory hands herself "@serve" under it
    let caller = Cap::root(&w.root, w.mallory.node_id(), API, SCHEMA, vec!["*".into()], window());
    let leaf = caller.delegate(&w.mallory, w.mallory.node_id(), vec![SERVE.into()], window()).unwrap();
    let p = prove(&w.mallory, &[caller, leaf], None, API, SCHEMA, &NONCE, TOKEN);
    assert!(check(&w, &p, None).unwrap_err().contains("link 0: not a serve cap"));
}

#[test]
fn expired_revoked_and_pinned_chains_are_refused() {
    let w = world();
    let old = Caveats { not_before: NOW - 7200, not_after: NOW - 3600, ..Default::default() };
    let chain = vec![serve_cap(&w.root, w.honest.node_id(), API, SCHEMA, None, old)];
    let p = prove(&w.honest, &chain, None, API, SCHEMA, &NONCE, TOKEN);
    assert!(check(&w, &p, None).is_err());

    let chain = vec![serve_cap(&w.root, w.honest.node_id(), API, SCHEMA, None, window())];
    let p = prove(&w.honest, &chain, None, API, SCHEMA, &NONCE, TOKEN);
    let nonce = chain[0].body.nonce;
    let root = w.root.node_id();
    let revoked = move |i: &[u8; 32], n: u64| *i == root && n == nonce;
    assert!(verify_serve(&[root], NOW, &asked(None), Some(&bytes(&p)), &revoked).unwrap_err().contains("revoked"));

    let build = cap_hash::cell_id(API, SCHEMA, "rev-a", &w.root.node_id());
    let chain = vec![serve_cap(&w.root, w.honest.node_id(), API, SCHEMA, Some(build), window())];
    let other = cap_hash::cell_id(API, SCHEMA, "rev-b", &w.root.node_id());
    let p = prove(&w.honest, &chain, Some(other), API, SCHEMA, &NONCE, TOKEN);
    assert!(check(&w, &p, None).unwrap_err().contains("pinned to another cell build"));
    let p = prove(&w.honest, &chain, Some(build), API, SCHEMA, &NONCE, TOKEN);
    assert!(check(&w, &p, None).is_ok());
}

mod r2 {
    ce_wire::api! {
        api R2 = "example.test.provider", version 1;
        types { pub struct K { pub k: u8 } }
        ops { 1 => Get(K) -> K, needs "r2:get"; }
    }
}
use r2::*;

/// Over a real socket: off by default (nothing asked, nothing checked), then a verifying client against a good
/// provider, a provider with no proof, a provider with a chain for another api, and one for another schema.
/// One test function: the two hooks are process-wide.
#[test]
fn over_the_wire() {
    use ce_wire::Api;
    let w = world();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    let s = blocking::Server::<R2>::new(|_h: &ce_wire::Hello| Ok(ce_wire::Caller { name: "t".into(), rights: vec!["*".into()] })).on::<Get, _>(|k: K, _| Ok(k));
    std::thread::spawn(move || s.serve(l));

    // off: no hooks, the call works exactly as before
    provider::enable_prover(w.honest.clone_identity(), vec![], None); // a prover alone changes nothing for a client that does not ask
    let c = blocking::Client::<R2>::connect(a, vec![]).unwrap();
    assert_eq!(c.call::<Get>(&K { k: 1 }).unwrap(), K { k: 1 });

    let root = w.root.node_id();
    ce_wire::provider::set_verifier(move |c, proof| {
        let asked = Asked { hello_api: c.hello_api, schema: c.schema, nonce: &c.ask.nonce, token: c.token, expect: None };
        verify_serve(&[root], now_s(), &asked, proof, &never).map(|_| ())
    });
    let refused = |why: &str| match blocking::Client::<R2>::connect(a, vec![]) {
        Err(WireError::Refused(Refusal::Gate(e))) => assert!(e.starts_with("provider: ") && e.contains(why), "{e}"),
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("accepted a provider that should be refused ({why})"),
    };
    let live = Caveats { not_before: now_s() - 60, not_after: now_s() + 3600, ..Default::default() };

    // a node with a valid key and no serve chain for this api
    refused("no serve proof");
    // a chain for another api
    provider::enable_prover(w.honest.clone_identity(), vec![vec![serve_cap(&w.root, w.honest.node_id(), "docs.read", R2::SCHEMA, None, live.clone())]], None);
    refused("no serve proof");
    // a chain for another schema of this api
    provider::enable_prover(w.honest.clone_identity(), vec![vec![serve_cap(&w.root, w.honest.node_id(), R2::NAME, R2::SCHEMA ^ 1, None, live.clone())]], None);
    refused("no serve proof");
    // self-rooted
    provider::enable_prover(w.mallory.clone_identity(), vec![vec![serve_cap(&w.mallory, w.mallory.node_id(), R2::NAME, R2::SCHEMA, None, live.clone())]], None);
    refused("not a serve root");
    // good
    provider::enable_prover(w.honest.clone_identity(), vec![vec![serve_cap(&w.root, w.honest.node_id(), R2::NAME, R2::SCHEMA, None, live)]], None);
    let c = blocking::Client::<R2>::connect(a, vec![]).unwrap();
    assert_eq!(c.call::<Get>(&K { k: 7 }).unwrap(), K { k: 7 });
    ce_wire::provider::clear();
}

fn now_s() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

trait CloneId {
    fn clone_identity(&self) -> Identity;
}
impl CloneId for Identity {
    fn clone_identity(&self) -> Identity {
        Identity::from_secret_bytes(&self.secret_bytes())
    }
}

/// Cost per connection, printed: `cargo test --release -p ce-gate --test provider cost -- --ignored --nocapture`.
#[test]
#[ignore]
fn cost() {
    let w = world();
    let mid = id(4);
    let n = 2000;
    for len in [1usize, 2, 3] {
        // a root serve cap with Resource::Any so it can be handed on; each hop keeps "@serve"
        let body = cap_hash::CapBody { v: 2, issuer: w.root.node_id(), subject: if len == 1 { w.honest.node_id() } else { mid.node_id() }, api: API.into(), schema: SCHEMA, cell: None, ops: vec![SERVE.into()], resource: ce_cap::Resource::Any, caveats: window(), nonce: 1, parent: None };
        let mut chain = vec![Cap::sign(&w.root, body).unwrap()];
        while chain.len() < len {
            let last = chain.last().unwrap().clone();
            let to = if chain.len() + 1 == len { w.honest.node_id() } else { mid.node_id() };
            chain.push(last.delegate(&mid, to, vec![SERVE.into()], window()).unwrap());
        }
        let t = std::time::Instant::now();
        let mut b = 0;
        for _ in 0..n {
            let p = prove(&w.honest, &chain, None, API, SCHEMA, &NONCE, TOKEN);
            b = bytes(&p).len();
        }
        let prove_us = t.elapsed().as_secs_f64() * 1e6 / n as f64;
        let pb = bytes(&prove(&w.honest, &chain, None, API, SCHEMA, &NONCE, TOKEN));
        let t = std::time::Instant::now();
        for _ in 0..n {
            verify_serve(&[w.root.node_id()], NOW, &asked(None), Some(&pb), &never).unwrap();
        }
        let verify_us = t.elapsed().as_secs_f64() * 1e6 / n as f64;
        println!("chain {len}: proof {b} bytes, prove {prove_us:.1} us, verify {verify_us:.1} us ({} ed25519 verifies)", 1 + len);
    }
}
