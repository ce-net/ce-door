//! A v2 cap named in the node's `revocations.json` as `(issuer, nonce)` is refused, and so is every chain under it.
use ce_cap::Caveats;
use ce_gate::cap_hash::Cap;
use ce_gate::{proof2, Gate};
use ce_identity::Identity;
use ce_wire::{Api, Hello};

#[allow(dead_code)]
mod bus {
    ce_wire::api! {
        api Bus = "example.test.caphash-revoke", version 1;
        types { pub struct Goal { pub id: u8 } }
        ops { 1 => SetGoal(Goal) -> Goal, needs "bus:goal"; }
    }
}
use bus::*;

#[test]
fn revoked_v2_cap_is_refused() {
    let dir = std::env::temp_dir().join(format!("ce-gate-caphash-revoke-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::env::set_var("CE_DATA_DIR", &dir);
    std::env::set_var("CE_WIRE_PEERS", "");
    let cell = Identity::from_secret_bytes(&[1; 32]);
    let alice = Identity::from_secret_bytes(&[2; 32]);
    let bob = Identity::from_secret_bytes(&[4; 32]);
    let g = Gate::<Bus>::new(cell.node_id(), vec![]);
    let a = Cap::root(&cell, alice.node_id(), Bus::NAME, Bus::SCHEMA, vec!["bus:goal".into()], Caveats::default());
    let b = a.delegate(&alice, bob.node_id(), vec!["bus:goal".into()], Caveats::default()).unwrap();
    let now = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    let h = |t| Hello { api: Bus::NAME.into(), version: 1, schema: Bus::SCHEMA, token: t, spawn: false };
    g.check(&h(proof2::<Bus>(&bob, &[a.clone(), b.clone()])), now()).unwrap();
    let rec = format!("{{\"records\":[{{\"issuer\":{:?},\"nonce\":{}}}]}}", cell.node_id(), a.body.nonce);
    std::fs::write(dir.join("revocations.json"), rec).unwrap();
    let e = g.check(&h(proof2::<Bus>(&bob, &[a, b])), now()).unwrap_err();
    assert!(e.contains("revoked"), "{e}");
}
