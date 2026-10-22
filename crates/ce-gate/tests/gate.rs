//! A blocking ce-wire cell gated by ce-cap: signed Hello, chain rooted at the cell's node, rights from abilities.
use ce_cap::{Caveats, Resource, SignedCapability};
use ce_gate::{proof, Gate};
use ce_identity::Identity;
use ce_wire::{blocking, Refusal, WireError};

mod bus {
    ce_wire::api! {
        api Bus = "example.test.gated", version 1;
        types { pub struct Goal { pub id: u8 } }
        ops { 1 => SetGoal(Goal) -> Goal, needs "bus:goal"; 2 => Reboot(()) -> (), needs "bus:admin"; }
    }
}
use bus::*;

fn cap(issuer: &Identity, to: &Identity, abilities: &[&str]) -> Vec<SignedCapability> {
    vec![SignedCapability::issue(issuer, to.node_id(), abilities.iter().map(|s| s.to_string()).collect(), Resource::Any, Caveats::default(), 7, None)]
}

#[test]
fn gate_grants_covered_rights_and_refuses_the_rest() {
    let cell = Identity::from_secret_bytes(&[1; 32]);
    let alice = Identity::from_secret_bytes(&[2; 32]);
    let mallory = Identity::from_secret_bytes(&[3; 32]);
    std::env::set_var("CE_DATA_DIR", std::env::temp_dir().join("ce-gate-test-none"));
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    let s = blocking::Server::<Bus>::new(Gate::<Bus>::new(cell.node_id(), vec![]).into_fn())
        .on::<SetGoal, _>(|g: Goal, _| Ok(g))
        .on::<Reboot, _>(|_, _| Ok(()));
    std::thread::spawn(move || s.serve(l));

    let chain = cap(&cell, &alice, &["bus:goal"]);
    let tok = proof::<Bus>(&alice, &chain);
    let c = blocking::Client::<Bus>::connect(a, tok.clone()).unwrap();
    assert_eq!(c.call::<SetGoal>(&Goal { id: 5 }).unwrap(), Goal { id: 5 });
    assert_eq!(c.call::<Reboot>(&()), Err(WireError::Refused(Refusal::Right("bus:admin".into()))));

    let gate = |t: Vec<u8>| match blocking::Client::<Bus>::connect(a, t) {
        Err(WireError::Refused(Refusal::Gate(e))) => e,
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("accepted"),
    };
    assert_eq!(gate(tok), "replayed hello");
    // Mallory presents Alice's chain with her own key: the leaf is not hers.
    assert!(gate(proof::<Bus>(&mallory, &chain)).contains("not held"));
    // A chain Mallory minted herself does not root at the cell.
    assert!(gate(proof::<Bus>(&mallory, &cap(&mallory, &mallory, &["*"]))).contains("accepted authority"));
    // A wildcard cap covers both rights.
    let c = blocking::Client::<Bus>::connect(a, proof::<Bus>(&alice, &cap(&cell, &alice, &["bus:*"]))).unwrap();
    c.call::<Reboot>(&()).unwrap();
    // Not a proof at all.
    assert!(gate(b"hello".to_vec()).contains("not a ce-gate proof"));
}

#[test]
fn path_prefix_caveat_reaches_the_cell() {
    let cell = Identity::from_secret_bytes(&[1; 32]);
    let alice = Identity::from_secret_bytes(&[2; 32]);
    std::env::set_var("CE_DATA_DIR", std::env::temp_dir().join("ce-gate-test-none"));
    let g = Gate::<Bus>::new(cell.node_id(), vec![]);
    let mk = |pp: Option<&str>, n: u64| {
        let cv = Caveats { path_prefix: pp.map(String::from), ..Default::default() };
        let chain = vec![SignedCapability::issue(&cell, alice.node_id(), vec!["bus:*".into()], Resource::Any, cv, n, None)];
        let h = ce_wire::Hello { api: "example.test.gated".into(), version: 1, schema: <Bus as ce_wire::Api>::SCHEMA, token: proof::<Bus>(&alice, &chain), spawn: false };
        g.check(&h, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64).unwrap()
    };
    assert_eq!(mk(Some("projects/a"), 1).path_prefix(), Some("projects/a"));
    assert_eq!(mk(None, 2).path_prefix(), None);
}

mod sneaky {
    ce_wire::api! {
        api Sneaky = "example.test.sneaky", version 1;
        types { pub struct N { pub n: u8 } }
        ops { 1 => Read(N) -> N, needs "sneaky:read"; 2 => Odd(N) -> N, needs "caveat:path_prefix=/"; }
    }
}

/// A cap whose abilities (or an API whose right) look like a `caveat:` entry must not forge or widen a prefix.
#[test]
fn caveat_shaped_rights_never_reach_the_cell() {
    let cell = Identity::from_secret_bytes(&[1; 32]);
    let alice = Identity::from_secret_bytes(&[2; 32]);
    std::env::set_var("CE_DATA_DIR", std::env::temp_dir().join("ce-gate-test-none"));
    let g = Gate::<sneaky::Sneaky>::new(cell.node_id(), vec![]);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    let who = |abilities: &[&str], pp: Option<&str>, n: u64| {
        let cv = Caveats { path_prefix: pp.map(String::from), ..Default::default() };
        let chain = vec![SignedCapability::issue(&cell, alice.node_id(), abilities.iter().map(|s| s.to_string()).collect(), Resource::Any, cv, n, None)];
        let h = ce_wire::Hello { api: "example.test.sneaky".into(), version: 1, schema: <sneaky::Sneaky as ce_wire::Api>::SCHEMA, token: proof::<sneaky::Sneaky>(&alice, &chain), spawn: false };
        g.check(&h, now).unwrap()
    };
    // Unconfined cap that also names the caveat right and the wildcard: still unconfined, no caveat entry.
    let w = who(&["*", "caveat:path_prefix=/", "sneaky:read"], None, 11);
    assert_eq!(w.path_prefix(), None);
    assert!(w.rights.iter().all(|r| !r.starts_with("caveat:")), "{:?}", w.rights);
    // The verified abilities are readable for per-resource rights.
    let w = who(&["sneaky:read", "sneaky:tool:*"], None, 13);
    assert!(w.grants("sneaky:tool:ls") && !w.grants("sneaky:tool") && !w.grants("sneaky:other:ls"));
    assert!(who(&["*"], None, 14).grants("anything:at:all"));
    // Confined cap: only the verified leaf prefix, never a second one smuggled through the abilities.
    let w = who(&["*", "caveat:path_prefix=/"], Some("proj"), 12);
    assert_eq!(w.path_prefix(), Some("proj"));
    assert_eq!(w.rights.iter().filter(|r| r.starts_with("caveat:")).count(), 1);
}

/// `cargo test --release -p ce-gate -- --ignored --nocapture`: cost of one gate check (sig + chain verify).
#[test]
#[ignore]
fn gate_cost() {
    let cell = Identity::from_secret_bytes(&[1; 32]);
    let alice = Identity::from_secret_bytes(&[2; 32]);
    let g = Gate::<Bus>::new(cell.node_id(), vec![]);
    let chain = cap(&cell, &alice, &["bus:*"]);
    let hellos: Vec<ce_wire::Hello> = (0..2000)
        .map(|_| ce_wire::Hello { api: "example.test.gated".into(), version: 1, schema: <Bus as ce_wire::Api>::SCHEMA, token: proof::<Bus>(&alice, &chain), spawn: false })
        .collect();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    let t = std::time::Instant::now();
    for h in &hellos {
        g.check(h, now).unwrap();
    }
    let per = t.elapsed().as_secs_f64() * 1e6 / hellos.len() as f64;
    let t = std::time::Instant::now();
    for _ in 0..2000 {
        proof::<Bus>(&alice, &chain);
    }
    println!("{{\"gate_check_us\":{per:.1},\"proof_us\":{:.1}}}", t.elapsed().as_secs_f64() * 1e6 / 2000.0);
}
