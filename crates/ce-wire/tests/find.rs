//! by_name through net.find: a stopped cell is started by the finder and the call succeeds; a dead replica fails over
//! to the next; a different schema is never dialed; a failed start reaches the caller as the typed Unreachable.
//! One test function: the env (door port, finder address) is process-wide.
use ce_wire::find::{Find, FindError, FindReply, FindReq, NetFind, Replica};
use ce_wire::{Api, Caller, Client, Server, WireError};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

mod demo {
    ce_wire::api! {
        api Demo = "example.test.find", version 2;
        types { pub struct N { pub x: u32 } }
        ops { 1 => Inc(N) -> N, needs "t.inc"; }
    }
}
use demo::{Demo, Inc, N};

fn open(_: &ce_wire::Hello) -> Result<Caller, String> {
    Ok(Caller { name: "t".into(), rights: vec!["t.inc".into(), "net.find:find".into()] })
}

/// Start the Demo cell on a fresh port; the cell "is running" from here on.
async fn start_demo() -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(Server::<Demo>::new(open).on::<Inc, _, _>(|n: N, _| async move { Ok(N { x: n.x + 1 }) }).serve(l));
    a
}

fn replica(addr: SocketAddr, schema: u64, healthy_ms: u32) -> Replica {
    Replica { addr: addr.to_string(), node: "n".into(), version: "2.0.0".into(), schema_hash: schema, healthy_ms }
}

#[derive(Default)]
struct Mesh {
    running: Option<SocketAddr>,
    starts: u32,
    asked: Vec<(String, u16)>,
    fail: Option<FindError>,
    extra: Vec<Replica>,
}

#[tokio::test]
async fn find_or_spawn() {
    // A door port nobody listens on and no peers: only the finder can answer.
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    std::env::set_var("CE_DOOR_PORT", free.to_string());
    std::env::set_var("CE_WIRE_PEERS", "");
    std::env::set_var("CE_NODE", "127.0.0.1:1");

    // The finder: answers find(name, major); when nothing runs it starts the cell (what net.mesh does with [launch]).
    let mesh = Arc::new(Mutex::new(Mesh::default()));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    std::env::set_var("CE_NET_FIND", l.local_addr().unwrap().to_string());
    let m2 = mesh.clone();
    let s = Server::<NetFind>::new(open).on::<Find, _, _>(move |r: FindReq, _| {
        let m = m2.clone();
        async move {
            m.lock().unwrap().asked.push((r.name.clone(), r.major));
            if let Some(e) = m.lock().unwrap().fail.clone() {
                return Ok(Err(e));
            }
            let (running, extra) = { let g = m.lock().unwrap(); (g.running, g.extra.clone()) };
            let (addr, spawned) = match running {
                Some(a) => (a, false),
                None => {
                    let a = start_demo().await;
                    let mut g = m.lock().unwrap();
                    g.running = Some(a);
                    g.starts += 1;
                    (a, true)
                }
            };
            let mut replicas = extra;
            replicas.push(replica(addr, Demo::SCHEMA, 5));
            Ok(Ok(FindReply { replicas, spawned }))
        }
    });
    tokio::spawn(s.serve(l));

    // 1. Cell stopped -> by_name succeeds -> it is running, started once.
    assert!(mesh.lock().unwrap().running.is_none());
    let c = Client::<Demo>::by_name(vec![]).await.unwrap();
    assert_eq!(c.call::<Inc>(&N { x: 41 }).await.unwrap().x, 42);
    assert!(mesh.lock().unwrap().running.is_some());
    assert_eq!(mesh.lock().unwrap().starts, 1);
    assert_eq!(mesh.lock().unwrap().asked[0], ("example.test.find".to_string(), 2));

    // 2. Running: the second by_name connects without a new start.
    let c = Client::<Demo>::by_name(vec![]).await.unwrap();
    assert_eq!(c.call::<Inc>(&N { x: 1 }).await.unwrap().x, 2);
    assert_eq!(mesh.lock().unwrap().starts, 1);

    // 3. Failover: a healthier replica that is dead is tried first, then the live one answers. A replica with another
    //    schema is never dialed (its address is a live Demo too: if dialed, the Hello would be refused, not accepted).
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let other_schema = start_demo().await;
    mesh.lock().unwrap().extra = vec![replica(dead, Demo::SCHEMA, 0), replica(other_schema, Demo::SCHEMA ^ 1, 0)];
    let reply = FindReply { replicas: mesh.lock().unwrap().extra.clone(), spawned: false };
    assert_eq!(ce_wire::find::usable::<Demo>(&reply), vec![dead.to_string()]);
    let c = Client::<Demo>::by_name(vec![]).await.unwrap();
    assert_eq!(c.call::<Inc>(&N { x: 9 }).await.unwrap().x, 10);

    // 4. A failed start reaches the caller typed: which cell, the dependency chain, the cause.
    let fail = FindError::StartFailed { cell: "state.store".into(), dep_chain: vec!["example.test.find".into(), "state.store".into()], cause: "exit 1".into() };
    mesh.lock().unwrap().fail = Some(fail.clone());
    match Client::<Demo>::by_name(vec![]).await {
        Err(WireError::Unreachable(u)) => {
            assert_eq!(u.find, Some(fail));
            assert_eq!((u.api.as_str(), u.major), ("example.test.find", 2));
            let shown = u.to_string();
            assert!(shown.contains("state.store failed (example.test.find -> state.store): exit 1"), "{shown}");
        }
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("connected though the start failed"),
    }
}
