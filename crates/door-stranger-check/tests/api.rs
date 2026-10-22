//! Every op through a real ce-wire connection; a caller without the right is refused.
use door_stranger_check_api::*;
use ce_wire::{Caller, Client, Server, WireError};

async fn serve(rights: &'static [&'static str]) -> std::net::SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let s = Server::<DoorStrangerCheck>::new(move |_| Ok(Caller { name: "t".into(), rights: rights.iter().map(|r| r.to_string()).collect() }))
        .on::<HealthOp, _, _>(|_: (), _| async move { Ok(Health { ok: true, version: "t".into(), uptime_s: 0 }) })
        .on::<Check, _, _>(|r: CheckReq, _| async move { Ok(tokio::task::spawn_blocking(move || door_stranger_check::check(r)).await.unwrap()) });
    tokio::spawn(s.serve(l));
    a
}

/// A cell behind a real ce-gate that roots only `root`: what a placed door does for a strangers' Hello.
async fn gated(root: ce_gate::ce_identity::NodeId) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let gate = ce_gate::Gate::<DoorStrangerCheck>::new(root, vec![root]).into_fn();
    let s = Server::<DoorStrangerCheck>::new(gate).on::<HealthOp, _, _>(|_: (), _| async move { Ok(Health { ok: true, version: "t".into(), uptime_s: 0 }) });
    tokio::spawn(s.serve(l));
    a.to_string()
}

/// A cell that lets anybody in: the check must say OPEN.
async fn open_door() -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let s = Server::<DoorStrangerCheck>::new(|_| Ok(Caller { name: "anyone".into(), rights: vec!["door.stranger-check:health".into()] }))
        .on::<HealthOp, _, _>(|_: (), _| async move { Ok(Health { ok: true, version: "t".into(), uptime_s: 0 }) });
    tokio::spawn(s.serve(l));
    a.to_string()
}

#[tokio::test]
async fn ops_and_refusal() {
    let c = Client::<DoorStrangerCheck>::connect(serve(&["door.stranger-check:health", "door.stranger-check:check"]).await, vec![]).await.unwrap();
    assert!(c.call::<HealthOp>(&()).await.unwrap().ok);
    let bad = CheckReq { addr: String::new(), apis: vec![], control: false };
    assert!(matches!(c.call::<Check>(&bad).await.unwrap(), Err(CheckError::Invalid(_))));
    let c = Client::<DoorStrangerCheck>::connect(serve(&["door.stranger-check:health"]).await, vec![]).await.unwrap();
    assert!(matches!(c.call::<Check>(&bad).await, Err(WireError::Refused(_))));
}

/// The three verdicts against real servers: a gated cell PASSes with its own key as control, an open one is OPEN,
/// and a gate that does not root our key makes the control fail, so the check refuses to call it PASS.
#[tokio::test(flavor = "multi_thread")]
async fn verdicts() {
    let dir = std::env::temp_dir().join(format!("dsc-test-{}", std::process::id()));
    std::env::set_var("CE_DATA_DIR", &dir);
    let me = ce_gate::node_identity().unwrap();
    let api = vec!["door.stranger-check".to_string()];

    let a = gated(me.node_id()).await;
    let rep = tokio::task::spawn_blocking({ let api = api.clone(); move || door_stranger_check::check(CheckReq { addr: a, apis: api, control: true }) }).await.unwrap().unwrap();
    assert_eq!(rep.verdict, "PASS", "{}", door_stranger_check::render(&rep));
    for who in ["anonymous", "stranger", "stranger-spawn"] {
        assert!(rep.rows.iter().any(|r| r.who == who && r.outcome == "REFUSED"), "{who}: {}", door_stranger_check::render(&rep));
    }
    assert!(rep.rows.iter().any(|r| r.who == "own-key" && r.outcome == "ACCEPTED"));

    let a = open_door().await;
    let rep = tokio::task::spawn_blocking({ let api = api.clone(); move || door_stranger_check::check(CheckReq { addr: a, apis: api, control: false }) }).await.unwrap().unwrap();
    assert_eq!(rep.verdict, "OPEN", "{}", door_stranger_check::render(&rep));

    let other = ce_gate::ce_identity::Identity::load_or_generate(&dir.join("other")).unwrap();
    let a = gated(other.node_id()).await;
    let rep = tokio::task::spawn_blocking(move || door_stranger_check::check(CheckReq { addr: a, apis: api, control: true })).await.unwrap().unwrap();
    assert_eq!(rep.verdict, "INCONCLUSIVE", "{}", door_stranger_check::render(&rep));
    let _ = std::fs::remove_dir_all(&dir);
}

/// sdk/py was generated from this api: a stale client is refused at connect with a schema error (102 of 261 cells
/// had drifted on 2026-10-15). After changing the api run `ce-wire-gen --lang py|ts|ts-web|swift`.
#[test]
fn sdk_matches_api() {
    // the run-time dir first: build.offload compiles on another node and runs the test here
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").into());
    let p = format!("{dir}/../../sdk/py/door_stranger_check.py");
    let py = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}: run ce-wire-gen --lang py"));
    let want = format!("SCHEMA = {}  #", <DoorStrangerCheck as ce_wire::Api>::SCHEMA);
    assert!(py.contains(&want), "{p} is stale (want {want}): run ce-wire-gen");
}
