//! A gate built from `mesh_roots()` follows the roots file: a node added later is rooted without restarting the
//! cell, and a fixed root set stays fixed.
use ce_cap::{Caveats, Resource, SignedCapability};
use ce_gate::{mesh_roots, proof, Gate};
use ce_identity::Identity;
use ce_wire::{blocking, WireError};

mod bus {
    ce_wire::api! {
        api Bus = "example.test.mesh-roots", version 1;
        types { pub struct Goal { pub id: u8 } }
        ops { 1 => SetGoal(Goal) -> Goal, needs "bus:goal"; }
    }
}
use bus::*;

fn hex(id: &[u8; 32]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn a_node_added_to_roots_is_rooted_without_a_restart() {
    let home = std::env::temp_dir().join(format!("ce-gate-mesh-roots-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join(".config/ce-wire")).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("CE_DATA_DIR", home.join("ce"));
    std::env::set_var("CE_WIRE_PEERS", "");
    std::env::set_var("CE_GATE_ROOTS_EVERY_MS", "100");
    let cell = Identity::from_secret_bytes(&[1; 32]);
    let other = Identity::from_secret_bytes(&[9; 32]);
    let serve = |roots| {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        let s = blocking::Server::<Bus>::new(Gate::<Bus>::new(cell.node_id(), roots).into_fn()).on::<SetGoal, _>(|g: Goal, _| Ok(g));
        std::thread::spawn(move || s.serve(l));
        a
    };
    let live = serve(mesh_roots());
    let fixed = serve(vec![[7u8; 32]]);
    // the other node's own cap, as its self proof is: rooted only where its key is a root
    let own = || proof::<Bus>(&other, &[SignedCapability::issue(&other, other.node_id(), vec!["bus:goal".into()], Resource::Any, Caveats::default(), 7, None)]);
    assert!(matches!(blocking::Client::<Bus>::connect(live, own()), Err(WireError::Refused(_))), "rooted before it was added");

    std::fs::write(home.join(".config/ce-wire/roots"), format!("{}  # the other node\n", hex(&other.node_id()))).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(250));
    let c = blocking::Client::<Bus>::connect(live, own()).expect("not rooted after it was added to the roots file");
    assert_eq!(c.call::<SetGoal>(&Goal { id: 4 }).unwrap(), Goal { id: 4 });
    assert!(matches!(blocking::Client::<Bus>::connect(fixed, own()), Err(WireError::Refused(_))), "a fixed root set followed the file");

    // a line scoped to other apis does not root it here; one naming this api does
    let roots = home.join(".config/ce-wire/roots");
    std::fs::write(&roots, format!("{} twin.registry,replica.probe\n", hex(&other.node_id()))).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(250));
    assert!(matches!(blocking::Client::<Bus>::connect(live, own()), Err(WireError::Refused(_))), "rooted by a line scoped to other apis");
    std::fs::write(&roots, format!("{} twin.registry,example.test.mesh-roots\n", hex(&other.node_id()))).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(250));
    assert!(blocking::Client::<Bus>::connect(live, own()).is_ok(), "a line naming this api did not root it");
    assert!(ce_gate::mesh_roots().is_empty(), "a scoped line counted for every api");
    assert_eq!(ce_gate::mesh_roots_for("twin.registry"), vec![other.node_id()]);

    // own-key only: a bare line (and any root the cell passes from mesh_roots) does not root it; a line naming it does
    std::fs::write(&roots, format!("{}\n", hex(&other.node_id()))).unwrap();
    std::fs::write(home.join(".config/ce-wire/own-key"), "example.test.mesh-roots  # like keys\n").unwrap();
    assert!(ce_gate::own_key_only("example.test.mesh-roots") && ce_gate::own_key_only("keys") && !ce_gate::own_key_only("twin.registry"));
    let mut passed = mesh_roots();
    passed.push(cell.node_id());
    assert_eq!(passed, vec![other.node_id(), cell.node_id()]);
    let own = serve(passed);
    assert!(matches!(blocking::Client::<Bus>::connect(own, proof_of(&other)), Err(WireError::Refused(_))), "own-key cell rooted by a bare line");
    assert!(blocking::Client::<Bus>::connect(own, proof_of(&cell)).is_ok(), "own-key cell refused its own key");
    std::fs::write(&roots, format!("{} example.test.mesh-roots\n", hex(&other.node_id()))).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(250));
    assert!(blocking::Client::<Bus>::connect(own, proof_of(&other)).is_ok(), "own-key cell ignored a line naming it");
    assert!(ce_gate::mesh_roots_for("example.test.mesh-roots") == vec![other.node_id()]);
    let _ = std::fs::remove_dir_all(&home);
}

fn proof_of(id: &Identity) -> Vec<u8> {
    proof::<Bus>(id, &[SignedCapability::issue(id, id.node_id(), vec!["bus:goal".into()], Resource::Any, Caveats::default(), 7, None)])
}
