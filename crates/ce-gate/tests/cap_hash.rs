//! Hash-id caps (v2) at the gate: forged, replayed, re-labelled, cross-api and cross-schema caps are refused, a chain
//! link whose issuer did not hold the right is refused, cell-pinned caps open one build only, and v1 caps still open a
//! cell that does not require v2 (counted), but not one that does.
use ce_cap::{Caveats, Resource, SignedCapability};
use ce_gate::cap_hash::{cap_hash, cell_id, Cap, CapBody};
use ce_gate::{legacy_accepted, proof, proof2, proof2_for, Gate, PROOF2_MAGIC};
use ce_identity::Identity;
use ce_wire::{Api, Hello};

#[allow(dead_code)]
mod bus {
    ce_wire::api! {
        api Bus = "example.test.caphash", version 1;
        types { pub struct Goal { pub id: u8 } }
        ops { 1 => SetGoal(Goal) -> Goal, needs "bus:goal"; 2 => Reboot(()) -> (), needs "bus:admin"; }
    }
}
use bus::*;

#[allow(dead_code)]
mod other {
    ce_wire::api! {
        api Other = "example.test.caphash-other", version 1;
        types { pub struct N { pub n: u8 } }
        ops { 1 => Read(N) -> N, needs "other:read"; }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

fn ids() -> (Identity, Identity, Identity) {
    std::env::set_var("CE_DATA_DIR", std::env::temp_dir().join("ce-gate-test-none"));
    std::env::set_var("CE_WIRE_PEERS", "");
    (Identity::from_secret_bytes(&[1; 32]), Identity::from_secret_bytes(&[2; 32]), Identity::from_secret_bytes(&[3; 32]))
}

fn hello<A: Api>(token: Vec<u8>) -> Hello {
    Hello { api: A::NAME.into(), version: A::VERSION, schema: A::SCHEMA, token, spawn: false }
}

fn root(cell: &Identity, to: &Identity, api: &str, schema: u64, ops: &[&str]) -> Cap {
    Cap::root(cell, to.node_id(), api, schema, ops.iter().map(|s| s.to_string()).collect(), Caveats::default())
}

fn ops(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[test]
fn a_v2_cap_opens_only_what_it_names() {
    let (cell, alice, _) = ids();
    let g = Gate::<Bus>::new(cell.node_id(), vec![]);
    let c = root(&cell, &alice, Bus::NAME, Bus::SCHEMA, &["bus:goal"]);
    let caller = g.check(&hello::<Bus>(proof2::<Bus>(&alice, &[c.clone()])), now_ms()).unwrap();
    assert!(caller.rights.contains(&"bus:goal".to_string()) && !caller.rights.contains(&"bus:admin".to_string()));
    // the audit grant id is the leaf cap's own hash id
    let want = format!("grant:{}", c.id[..8].iter().map(|b| format!("{b:02x}")).collect::<String>());
    assert!(caller.rights.contains(&want), "{:?}", caller.rights);
    // `*` in a v2 cap is every right of this api only
    let star = root(&cell, &alice, Bus::NAME, Bus::SCHEMA, &["*"]);
    let r = g.check(&hello::<Bus>(proof2::<Bus>(&alice, &[star])), now_ms()).unwrap().rights;
    assert!(r.contains(&"bus:admin".into()) && r.contains(&"bus:goal".into()));
}

#[test]
fn replayed_v2_hello_is_refused() {
    let (cell, alice, _) = ids();
    let g = Gate::<Bus>::new(cell.node_id(), vec![]);
    let h = hello::<Bus>(proof2::<Bus>(&alice, &[root(&cell, &alice, Bus::NAME, Bus::SCHEMA, &["bus:goal"])]));
    g.check(&h, now_ms()).unwrap();
    assert_eq!(g.check(&h, now_ms()).unwrap_err(), "replayed hello");
}

#[test]
fn stolen_cap_is_refused_for_another_key() {
    let (cell, alice, mallory) = ids();
    let g = Gate::<Bus>::new(cell.node_id(), vec![]);
    let c = root(&cell, &alice, Bus::NAME, Bus::SCHEMA, &["bus:*"]);
    // Mallory presents Alice's cap with her own key
    assert!(g.check(&hello::<Bus>(proof2::<Bus>(&mallory, &[c.clone()])), now_ms()).unwrap_err().contains("not held"));
    // Mallory swaps the subject to herself: the id no longer recomputes
    let mut forged = c.clone();
    forged.body.subject = mallory.node_id();
    let e = g.check(&hello::<Bus>(proof2::<Bus>(&mallory, &[forged.clone()])), now_ms()).unwrap_err();
    assert!(e.contains("id does not match"), "{e}");
    // ... and with the id recomputed, the cell never signed it
    forged.id = cap_hash(&forged.body);
    let e = g.check(&hello::<Bus>(proof2::<Bus>(&mallory, &[forged])), now_ms()).unwrap_err();
    assert!(e.contains("not the issuer's"), "{e}");
    // A cap Mallory mints herself, naming the cell as issuer, is not signed by the cell
    let body = CapBody { issuer: cell.node_id(), subject: mallory.node_id(), ..c.body.clone() };
    let fake = Cap { id: cap_hash(&body), body, sig: c.sig.clone() };
    assert!(g.check(&hello::<Bus>(proof2::<Bus>(&mallory, &[fake])), now_ms()).unwrap_err().contains("not the issuer's"));
    // Her own self-rooted cap does not root at the cell
    let own = root(&mallory, &mallory, Bus::NAME, Bus::SCHEMA, &["*"]);
    assert!(g.check(&hello::<Bus>(proof2::<Bus>(&mallory, &[own])), now_ms()).unwrap_err().contains("accepted authority"));
}

#[test]
fn relabelled_cap_is_refused() {
    let (cell, alice, _) = ids();
    let g = Gate::<Bus>::new(cell.node_id(), vec![]);
    // a cap that expires in 60 s, confined to one path and one node
    let cv = Caveats { not_after: now_ms() / 1000 + 60, path_prefix: Some("proj/a".into()), ..Default::default() };
    let mut body = Cap::root(&cell, alice.node_id(), Bus::NAME, Bus::SCHEMA, ops(&["bus:goal"]), cv).body;
    body.resource = Resource::Node(cell.node_id());
    let c = Cap::sign(&cell, body).unwrap();
    g.check(&hello::<Bus>(proof2::<Bus>(&alice, &[c.clone()])), now_ms()).unwrap();
    let edits: [fn(&mut CapBody); 5] = [
        |b| b.ops.push("bus:admin".into()),
        |b| b.caveats.not_after += 1_000_000,
        |b| b.caveats.path_prefix = None,
        |b| b.resource = Resource::Any,
        |b| b.nonce ^= 1,
    ];
    for edit in edits {
        let mut x = c.clone();
        edit(&mut x.body);
        let e = g.check(&hello::<Bus>(proof2::<Bus>(&alice, &[x])), now_ms()).unwrap_err();
        assert!(e.contains("id does not match"), "{e}");
    }
    // a garbage tail after the magic is not a v2 proof, and is never retried as v1
    let mut t = PROOF2_MAGIC.to_vec();
    t.extend_from_slice(&proof::<Bus>(&alice, &[]));
    assert!(g.check(&hello::<Bus>(t), now_ms()).unwrap_err().contains("not a ce-gate v2 proof"));
}

#[test]
fn cross_schema_and_cross_api_caps_are_refused() {
    let (cell, alice, _) = ids();
    let g = Gate::<Bus>::new(cell.node_id(), vec![]);
    // a cap for another schema of this api (an older or newer build the cell does not answer)
    let old = root(&cell, &alice, Bus::NAME, Bus::SCHEMA ^ 1, &["bus:*"]);
    let e = g.check(&hello::<Bus>(proof2::<Bus>(&alice, &[old])), now_ms()).unwrap_err();
    assert!(e.contains("schema"), "{e}");
    // a cap for another api, even with `*`
    let o = root(&cell, &alice, other::Other::NAME, other::Other::SCHEMA, &["*"]);
    let e = g.check(&hello::<Bus>(proof2::<Bus>(&alice, &[o])), now_ms()).unwrap_err();
    assert!(e.contains("not example.test.caphash"), "{e}");
    // a cap for one instance does not open another instance of the same api
    let inst = root(&cell, &alice, &ce_wire::instance_key(Bus::NAME, "a"), Bus::SCHEMA, &["bus:*"]);
    let mut h = hello::<Bus>(ce_gate::proof2_as::<Bus>(&alice, &[inst.clone()], "b"));
    h.api = ce_wire::instance_key(Bus::NAME, "b");
    assert!(g.check(&h, now_ms()).unwrap_err().contains("cap is for api"));
    let mut h = hello::<Bus>(ce_gate::proof2_as::<Bus>(&alice, &[inst], "a"));
    h.api = ce_wire::instance_key(Bus::NAME, "a");
    g.check(&h, now_ms()).unwrap();
    // the Hello is signed over its api and schema: a proof for another api does not verify here
    let p = proof2_for(&alice, &[root(&cell, &alice, Bus::NAME, Bus::SCHEMA, &["*"])], other::Other::NAME, other::Other::SCHEMA);
    assert_eq!(g.check(&hello::<Bus>(p), now_ms()).unwrap_err(), "bad hello signature");
}

#[test]
fn a_link_whose_issuer_did_not_hold_the_right_is_refused() {
    let (cell, alice, mallory) = ids();
    let g = Gate::<Bus>::new(cell.node_id(), vec![]);
    let a = root(&cell, &alice, Bus::NAME, Bus::SCHEMA, &["bus:goal"]);
    // proper delegation: alice -> mallory, narrower
    let m = a.delegate(&alice, mallory.node_id(), ops(&["bus:goal"]), Caveats::default()).unwrap();
    g.check(&hello::<Bus>(proof2::<Bus>(&mallory, &[a.clone(), m.clone()])), now_ms()).unwrap();
    // widening: alice hands on bus:admin she never held
    let wide = a.delegate(&alice, mallory.node_id(), ops(&["bus:admin"]), Caveats::default()).unwrap();
    assert!(g.check(&hello::<Bus>(proof2::<Bus>(&mallory, &[a.clone(), wide])), now_ms()).unwrap_err().contains("ops exceed"));
    // mallory signs a child of alice's cap herself (she is not its subject)
    let stolen = a.delegate(&mallory, mallory.node_id(), ops(&["bus:goal"]), Caveats::default()).unwrap();
    assert!(g.check(&hello::<Bus>(proof2::<Bus>(&mallory, &[a.clone(), stolen])), now_ms()).unwrap_err().contains("did not hold"));
    // a child that names another parent
    let b = root(&cell, &alice, Bus::NAME, Bus::SCHEMA, &["bus:goal"]);
    let m2 = b.delegate(&alice, mallory.node_id(), ops(&["bus:goal"]), Caveats::default()).unwrap();
    assert!(g.check(&hello::<Bus>(proof2::<Bus>(&mallory, &[a.clone(), m2])), now_ms()).unwrap_err().contains("parent id"));
    // a child that outlives an expiring parent
    let short = Cap::root(&cell, alice.node_id(), Bus::NAME, Bus::SCHEMA, ops(&["bus:goal"]), Caveats { not_after: now_ms() / 1000 + 60, ..Default::default() });
    let long = short.delegate(&alice, mallory.node_id(), ops(&["bus:goal"]), Caveats::default()).unwrap();
    assert!(g.check(&hello::<Bus>(proof2::<Bus>(&mallory, &[short, long])), now_ms()).unwrap_err().contains("caveats are broader"));
    // a child that moves to another schema
    let mut body = m.body.clone();
    body.schema ^= 1;
    let x = Cap::sign(&alice, body).unwrap();
    assert!(g.check(&hello::<Bus>(proof2::<Bus>(&mallory, &[a, x])), now_ms()).unwrap_err().contains("schema"));
}

#[test]
fn expired_and_not_yet_valid_caps_are_refused() {
    let (cell, alice, _) = ids();
    let g = Gate::<Bus>::new(cell.node_id(), vec![]);
    let now = now_ms() / 1000;
    let mk = |cv: Caveats| Cap::root(&cell, alice.node_id(), Bus::NAME, Bus::SCHEMA, ops(&["bus:goal"]), cv);
    let e = g.check(&hello::<Bus>(proof2::<Bus>(&alice, &[mk(Caveats { not_after: now - 5, ..Default::default() })])), now_ms()).unwrap_err();
    assert!(e.contains("expired"), "{e}");
    let e = g.check(&hello::<Bus>(proof2::<Bus>(&alice, &[mk(Caveats { not_before: now + 600, ..Default::default() })])), now_ms()).unwrap_err();
    assert!(e.contains("not yet valid"), "{e}");
}

#[test]
fn cell_pinned_cap_opens_one_build_only() {
    let (cell, alice, _) = ids();
    let pin = |rev: &str| {
        let mut b = root(&cell, &alice, Bus::NAME, Bus::SCHEMA, &["bus:goal"]).body;
        b.cell = Some(cell_id(Bus::NAME, Bus::SCHEMA, rev, &cell.node_id()));
        Cap::sign(&cell, b).unwrap()
    };
    let g = Gate::<Bus>::new(cell.node_id(), vec![]).cell("rev-a", &cell.node_id());
    assert_eq!(g.cell_id(), Some(cell_id(Bus::NAME, Bus::SCHEMA, "rev-a", &cell.node_id())));
    g.check(&hello::<Bus>(proof2::<Bus>(&alice, &[pin("rev-a")])), now_ms()).unwrap();
    assert!(g.check(&hello::<Bus>(proof2::<Bus>(&alice, &[pin("rev-b")])), now_ms()).unwrap_err().contains("another cell build"));
    // a gate that does not know its build refuses every pinned cap
    let blind = Gate::<Bus>::new(cell.node_id(), vec![]);
    assert!(blind.check(&hello::<Bus>(proof2::<Bus>(&alice, &[pin("rev-a")])), now_ms()).unwrap_err().contains("another cell build"));
    // a child may not drop its parent's pin
    let p = pin("rev-a");
    let mut b = p.delegate(&alice, alice.node_id(), ops(&["bus:goal"]), Caveats::default()).unwrap().body;
    b.cell = None;
    let child = Cap::sign(&alice, b).unwrap();
    assert!(g.check(&hello::<Bus>(proof2::<Bus>(&alice, &[p, child])), now_ms()).unwrap_err().contains("cell differs"));
}

#[test]
fn v1_caps_are_counted_and_refused_where_v2_is_required() {
    let (cell, alice, _) = ids();
    let v1 = vec![SignedCapability::issue(&cell, alice.node_id(), ops(&["bus:goal"]), Resource::Any, Caveats::default(), 9, None)];
    let before = legacy_accepted();
    Gate::<Bus>::new(cell.node_id(), vec![]).check(&hello::<Bus>(proof::<Bus>(&alice, &v1)), now_ms()).unwrap();
    assert!(legacy_accepted() > before);
    let strict = Gate::<Bus>::new(cell.node_id(), vec![]).require_v2();
    let e = strict.check(&hello::<Bus>(proof::<Bus>(&alice, &v1)), now_ms()).unwrap_err();
    assert!(e.contains("v2"), "{e}");
    strict.check(&hello::<Bus>(proof2::<Bus>(&alice, &[root(&cell, &alice, Bus::NAME, Bus::SCHEMA, &["bus:goal"])])), now_ms()).unwrap();
}

#[test]
fn a_v2_chain_longer_than_the_limit_is_refused() {
    let (cell, alice, _) = ids();
    let g = Gate::<Bus>::new(cell.node_id(), vec![]);
    let mut chain = vec![root(&cell, &alice, Bus::NAME, Bus::SCHEMA, &["bus:goal"])];
    for _ in 0..ce_gate::cap_hash::MAX_CHAIN {
        let next = chain.last().unwrap().delegate(&alice, alice.node_id(), ops(&["bus:goal"]), Caveats::default()).unwrap();
        chain.push(next);
    }
    assert!(g.check(&hello::<Bus>(proof2::<Bus>(&alice, &chain)), now_ms()).unwrap_err().contains("longer than"));
}

/// End to end over a real blocking server: a v2 token opens the cell and its per-op rights hold.
#[test]
fn v2_token_over_the_wire() {
    use ce_wire::{blocking, Refusal, WireError};
    let (cell, alice, _) = ids();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    let s = blocking::Server::<Bus>::new(Gate::<Bus>::new(cell.node_id(), vec![]).require_v2().into_fn())
        .on::<SetGoal, _>(|g: Goal, _| Ok(g))
        .on::<Reboot, _>(|_, _| Ok(()));
    std::thread::spawn(move || s.serve(l));
    let c = blocking::Client::<Bus>::connect(a, proof2::<Bus>(&alice, &[root(&cell, &alice, Bus::NAME, Bus::SCHEMA, &["bus:goal"])])).unwrap();
    assert_eq!(c.call::<SetGoal>(&Goal { id: 3 }).unwrap(), Goal { id: 3 });
    assert_eq!(c.call::<Reboot>(&()), Err(WireError::Refused(Refusal::Right("bus:admin".into()))));
    let v1 = vec![SignedCapability::issue(&cell, alice.node_id(), ops(&["bus:*"]), Resource::Any, Caveats::default(), 5, None)];
    match blocking::Client::<Bus>::connect(a, proof::<Bus>(&alice, &v1)) {
        Err(WireError::Refused(Refusal::Gate(e))) => assert!(e.contains("v2"), "{e}"),
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("v1 accepted by a v2-only cell"),
    }
}
