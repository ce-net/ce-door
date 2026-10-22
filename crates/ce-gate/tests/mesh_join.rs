//! A node that joins net.mesh after a cell started is rooted on its first call, at the default re-read interval
//! (30 s): the refusal itself re-reads the peers file (before this, a cell refused a
//! freshly joined node until the cell was restarted). A stranger never in the peers file stays refused.
use ce_cap::{Caveats, Resource, SignedCapability};
use ce_gate::{mesh_roots, proof, Gate};
use ce_identity::Identity;
use ce_wire::{blocking, WireError};

mod bus {
    ce_wire::api! {
        api Bus = "example.test.mesh-join", version 1;
        types { pub struct Goal { pub id: u8 } }
        ops { 1 => SetGoal(Goal) -> Goal, needs "bus:goal"; }
    }
}
use bus::*;

fn hex(id: &[u8; 32]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn self_proof(id: &Identity) -> Vec<u8> {
    proof::<Bus>(id, &[SignedCapability::issue(id, id.node_id(), vec!["bus:goal".into()], Resource::Any, Caveats::default(), 7, None)])
}

#[test]
fn a_node_that_joins_after_the_cell_started_is_rooted_on_its_first_call() {
    let home = std::env::temp_dir().join(format!("ce-gate-mesh-join-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join(".config/ce-wire")).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("CE_DATA_DIR", home.join("ce"));
    std::env::remove_var("CE_WIRE_PEERS");
    std::env::remove_var("CE_GATE_ROOTS_EVERY_MS"); // the real 30 s interval
    let peers = home.join(".config/ce-wire/peers");
    let cell = Identity::from_secret_bytes(&[1; 32]);
    let old = Identity::from_secret_bytes(&[2; 32]);
    let joiner = Identity::from_secret_bytes(&[3; 32]);
    let stranger = Identity::from_secret_bytes(&[4; 32]);
    std::fs::write(&peers, format!("10.0.1.2 {}\n", hex(&old.node_id()))).unwrap();

    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let at = l.local_addr().unwrap();
    let s = blocking::Server::<Bus>::new(Gate::<Bus>::new(cell.node_id(), mesh_roots()).into_fn()).on::<SetGoal, _>(|g: Goal, _| Ok(g));
    std::thread::spawn(move || s.serve(l));

    let t0 = std::time::Instant::now();
    assert!(blocking::Client::<Bus>::connect(at, self_proof(&old)).is_ok(), "a peer from the start was refused");
    assert!(matches!(blocking::Client::<Bus>::connect(at, self_proof(&joiner)), Err(WireError::Refused(_))), "rooted before it joined");

    // net.mesh adds the new node to the peers file; it calls right away, long before the 30 s re-read
    std::thread::sleep(std::time::Duration::from_millis(1100));
    std::fs::write(&peers, format!("10.0.1.2 {}\n10.0.1.3 {}\n", hex(&old.node_id()), hex(&joiner.node_id()))).unwrap();
    let c = blocking::Client::<Bus>::connect(at, self_proof(&joiner)).expect("a node that joined was refused until the next 30 s re-read");
    assert_eq!(c.call::<SetGoal>(&Goal { id: 5 }).unwrap(), Goal { id: 5 });
    assert!(t0.elapsed() < std::time::Duration::from_secs(10), "took {:?}", t0.elapsed());

    assert!(matches!(blocking::Client::<Bus>::connect(at, self_proof(&stranger)), Err(WireError::Refused(_))), "a stranger was rooted");
    // a node that leaves the mesh is dropped by the same re-read
    std::fs::write(&peers, format!("10.0.1.3 {}\n", hex(&joiner.node_id()))).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert!(matches!(blocking::Client::<Bus>::connect(at, self_proof(&stranger)), Err(WireError::Refused(_))));
    assert!(blocking::Client::<Bus>::connect(at, self_proof(&joiner)).is_ok());
    let _ = std::fs::remove_dir_all(&home);
}
