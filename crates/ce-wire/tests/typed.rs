use ce_wire::{Caller, Client, Refusal, Server, WireError};

mod v1 {
    ce_wire::api! {
        api Bus = "servo.bus.test", version 1;
        types { pub struct Goal { pub id: u8, pub counts: i16 } pub struct Ack { pub ok: bool } }
        ops { 1 => SetGoal(Goal) -> Ack, needs "servo.goal"; 2 => Stop(()) -> Ack, needs "servo.stop"; }
    }
}
mod v1b {
    // Same name and ops, one field type changed: must be refused at connect.
    ce_wire::api! {
        api Bus = "servo.bus.test", version 1;
        types { pub struct Goal { pub id: u8, pub counts: i32 } pub struct Ack { pub ok: bool } }
        ops { 1 => SetGoal(Goal) -> Ack, needs "servo.goal"; 2 => Stop(()) -> Ack, needs "servo.stop"; }
    }
}

async fn serve() -> std::net::SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let s = Server::<v1::Bus>::new(|h| match h.token.as_slice() {
        b"goal" => Ok(Caller { name: "policy".into(), rights: vec!["servo.goal".into()] }),
        _ => Err("unknown token".into()),
    })
    .on::<v1::SetGoal, _, _>(|g: v1::Goal, _| async move { Ok(v1::Ack { ok: g.counts > 0 }) })
    .on::<v1::Stop, _, _>(|_: (), _| async move { Ok(v1::Ack { ok: true }) });
    tokio::spawn(s.serve(l));
    a
}

#[tokio::test]
async fn typed_call_works() {
    let a = serve().await;
    let c = Client::<v1::Bus>::connect(a, b"goal".to_vec()).await.unwrap();
    assert_eq!(c.call::<v1::SetGoal>(&v1::Goal { id: 3, counts: 512 }).await.unwrap(), v1::Ack { ok: true });
}

#[tokio::test]
async fn missing_right_refused() {
    let a = serve().await;
    let c = Client::<v1::Bus>::connect(a, b"goal".to_vec()).await.unwrap();
    assert_eq!(c.call::<v1::Stop>(&()).await, Err(WireError::Refused(Refusal::Right("servo.stop".into()))));
}

#[tokio::test]
async fn stranger_refused() {
    let a = serve().await;
    match Client::<v1::Bus>::connect(a, b"nobody".to_vec()).await {
        Err(e) => assert_eq!(e, WireError::Refused(Refusal::Gate("unknown token".into()))),
        Ok(_) => panic!("stranger accepted"),
    }
}

#[tokio::test]
async fn schema_change_refused() {
    let a = serve().await;
    assert_ne!(<v1::Bus as ce_wire::Api>::SCHEMA, <v1b::Bus as ce_wire::Api>::SCHEMA);
    // wire 3: Stop hashes the same, so the caller is let in op by op and only the op
    // whose type changed is refused, on the call, with both per-op hashes
    let c = Client::<v1b::Bus>::connect(a, b"goal".to_vec()).await.expect("let in op by op");
    match c.call::<v1b::SetGoal>(&v1b::Goal { id: 1, counts: 5 }).await {
        Err(WireError::Refused(Refusal::SchemaMismatch { op: 1, ours, theirs, .. })) => {
            assert_eq!((ours, theirs), (ce_wire::op_hash::<v1::SetGoal>(), ce_wire::op_hash::<v1b::SetGoal>()));
        }
        r => panic!("expected SchemaMismatch for SetGoal, got {r:?}"),
    }
}

#[tokio::test]
async fn datagrams_drop_stale_and_strangers() {
    use ce_wire::{rights, DatagramSocket};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let s = Server::<v1::Bus>::new(|h| match h.token.as_slice() {
        b"goal" => Ok(Caller { name: "policy".into(), rights: vec!["servo.goal".into()] }),
        _ => Err("unknown token".into()),
    });
    let sessions = s.sessions();
    let mut rx = DatagramSocket::<v1::Bus>::bind("127.0.0.1:0", Some(sessions)).await.unwrap();
    let to = rx.local_addr().unwrap();
    tokio::spawn(s.serve(l));
    let tx = DatagramSocket::<v1::Bus>::bind("127.0.0.1:0", None).await.unwrap();
    let rights = rights![v1::SetGoal, v1::Stop];
    // Stranger: a made-up session key, dropped.
    tx.send::<v1::SetGoal>(to, 12345, &v1::Goal { id: 1, counts: 1 }).await.unwrap();
    let c = Client::<v1::Bus>::connect(a, b"goal".to_vec()).await.unwrap();
    tx.send::<v1::SetGoal>(to, c.session(), &v1::Goal { id: 1, counts: 2 }).await.unwrap();
    let d = rx.recv(&rights).await.unwrap();
    assert_eq!(d.decode::<v1::SetGoal>(), Some(v1::Goal { id: 1, counts: 2 }));
    assert_eq!(d.decode::<v1::Stop>(), None);
    // Missing right: dropped. Then a fresh goal arrives.
    tx.send::<v1::Stop>(to, c.session(), &()).await.unwrap();
    tx.send::<v1::SetGoal>(to, c.session(), &v1::Goal { id: 1, counts: 3 }).await.unwrap();
    assert_eq!(rx.recv(&rights).await.unwrap().decode::<v1::SetGoal>().unwrap().counts, 3);
}

mod named {
    ce_wire::api! {
        api Named = "example.test.byname", version 1;
        types { pub struct N { pub x: u32 } }
        ops { 1 => Inc(N) -> N, needs "t.inc"; }
    }
}

#[tokio::test]
async fn door_hands_sockets_to_cells() {
    // One process-wide door for this test binary: env is shared, so only this test sets it.
    let dir = std::env::temp_dir().join(format!("ce-door-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let port = { std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() };
    std::env::set_var("CE_DOOR_PORT", port.to_string());
    std::env::set_var("CE_DOOR_SOCK", dir.join("door.sock"));
    std::env::set_var("CE_WIRE_PEERS", "");
    std::env::set_var("CE_WIRE_APPS", &dir); // no manifests: nothing can be spawned
    tokio::spawn(ce_wire::run_door(vec![([127, 0, 0, 1], port).into()], dir.join("door.sock")));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Not running anywhere and no manifest: a typed refusal, not a hang.
    match Client::<named::Named>::by_name(vec![]).await {
        Err(WireError::Unreachable(u)) if u.cause.contains("NoCell") => {}
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("connected to nothing"),
    }

    // Two processes of the same cell register; the door spreads connections over both.
    for tag in [1000u32, 2000] {
        let s = Server::<named::Named>::new(|_| Ok(Caller { name: "t".into(), rights: vec!["t.inc".into()] }))
            .on::<named::Inc, _, _>(move |n: named::N, _| async move { Ok(named::N { x: n.x + tag }) });
        tokio::spawn(s.serve_door());
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..6 {
        let c = Client::<named::Named>::by_name(vec![]).await.unwrap();
        seen.insert(c.call::<named::Inc>(&named::N { x: 1 }).await.unwrap().x);
    }
    assert_eq!(seen.into_iter().collect::<Vec<_>>(), vec![1001, 2001]);

    // LIST keeps its two fields; LIST schema adds the schema hash every process registered.
    let ask = |q: &'static str| {
        let sock = dir.join("door.sock");
        async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut u = tokio::net::UnixStream::connect(sock).await.unwrap();
            u.write_all(format!("{q}\n").as_bytes()).await.unwrap();
            let mut out = String::new();
            u.read_to_string(&mut out).await.unwrap();
            out.lines().find(|l| l.starts_with("example.test.byname ")).unwrap().to_string()
        }
    };
    assert_eq!(ask("LIST").await, "example.test.byname 2");
    let want = format!("example.test.byname 2 {:016x}", <named::Named as ce_wire::Api>::SCHEMA);
    assert_eq!(ask("LIST schema").await, want);
}

mod ui {
    ce_wire::api! {
        api Ui = "example.test.ui", version 1;
        types { pub struct Watch { pub from: u32 } pub struct State { pub n: u32 } }
        ops { 1 => Bump(()) -> State, needs "ui.write"; }
        streams { 2 => Live(Watch) -> stream State, needs "ui.read"; 3 => Secret(Watch) -> stream State, needs "ui.admin"; }
    }
}

#[tokio::test]
async fn stream_snapshot_then_deltas_and_cancel() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let ended = std::sync::Arc::new(tokio::sync::Notify::new());
    let e2 = ended.clone();
    let s = Server::<ui::Ui>::new(|_| Ok(Caller { name: "phone".into(), rights: vec!["ui.read".into()] }))
        .stream::<ui::Live, _, _>(move |w: ui::Watch, _, sink| {
            let e2 = e2.clone();
            async move {
                let mut n = w.from;
                while sink.send(&ui::State { n }).is_ok() {
                    n += 1;
                    if n == w.from + 3 && w.from == 100 {
                        return Ok(()); // a finite stream ends normally
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                }
                e2.notify_one(); // client cancelled
                Ok(())
            }
        });
    tokio::spawn(s.serve(l));
    let c = Client::<ui::Ui>::connect(a, vec![]).await.unwrap();
    // Finite stream: 100, 101, 102, then a normal end.
    let mut f = c.subscribe::<ui::Live>(&ui::Watch { from: 100 }).unwrap();
    let mut got = vec![];
    while let Some(x) = f.next().await { got.push(x.unwrap().n) }
    assert_eq!(got, vec![100, 101, 102]);
    // Endless stream: snapshot first, then deltas; dropping it stops the server handler.
    let mut sub = c.subscribe::<ui::Live>(&ui::Watch { from: 7 }).unwrap();
    assert_eq!(sub.next().await.unwrap().unwrap().n, 7);
    assert_eq!(sub.next().await.unwrap().unwrap().n, 8);
    drop(sub);
    tokio::time::timeout(std::time::Duration::from_secs(1), ended.notified()).await.expect("handler saw the cancel");
    // A stream without the right is refused with the right's name.
    let mut x = c.subscribe::<ui::Secret>(&ui::Watch { from: 0 }).unwrap();
    match x.next().await {
        Some(Err(WireError::Refused(Refusal::UnknownOp(3)))) | Some(Err(WireError::Refused(Refusal::Right(_)))) => {}
        other => panic!("{:?}", other.map(|r| r.map(|s| s.n))),
    }
}

/// `connect_stream`: the same client over a stream opened by someone else (here a TCP stream, as a WebSocket bridge or
/// a pipe would hand it over); the gate still decides.
#[tokio::test]
async fn connect_stream_over_an_open_stream() {
    let a = serve().await;
    let s = tokio::net::TcpStream::connect(a).await.unwrap();
    let c = Client::<v1::Bus>::connect_stream(s, b"goal".to_vec()).await.unwrap();
    assert_eq!(c.call::<v1::SetGoal>(&v1::Goal { id: 1, counts: 9 }).await.unwrap(), v1::Ack { ok: true });
    let (x, y) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        let mut t = tokio::net::TcpStream::connect(a).await.unwrap();
        let mut y = y;
        let _ = tokio::io::copy_bidirectional(&mut y, &mut t).await;
    });
    assert!(matches!(Client::<v1::Bus>::connect_stream(x, b"nobody".to_vec()).await, Err(WireError::Refused(_))));
}

/// A dropped client closes its socket even when the far side never closes first: a relay (ce-node :7700) holds the
/// server end open, so a reader task kept alive past the drop leaked one socket per call.
#[tokio::test]
async fn dropped_client_closes_socket() {
    use tokio::io::AsyncReadExt;
    let a = serve().await;
    let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ra = relay.local_addr().unwrap();
    let (eof_tx, eof_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut c, _) = relay.accept().await.unwrap();
        let s = tokio::net::TcpStream::connect(a).await.unwrap();
        let (mut cr, mut cw) = c.split();
        let (mut sr, mut sw) = tokio::io::split(s);
        let up = async {
            let mut b = [0u8; 4096];
            loop {
                match cr.read(&mut b).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => tokio::io::AsyncWriteExt::write_all(&mut sw, &b[..n]).await.unwrap(),
                }
            }
        };
        // Like the relay: the server half stays open, so only the client can end this connection.
        tokio::select! { _ = up => {}, _ = tokio::io::copy(&mut sr, &mut cw) => { std::future::pending::<()>().await } }
        let _ = eof_tx.send(());
        std::future::pending::<()>().await;
    });
    let c = Client::<v1::Bus>::connect(ra, b"goal".to_vec()).await.unwrap();
    assert_eq!(c.call::<v1::SetGoal>(&v1::Goal { id: 1, counts: 1 }).await.unwrap(), v1::Ack { ok: true });
    drop(c);
    tokio::time::timeout(std::time::Duration::from_secs(5), eof_rx).await.expect("socket still open 5 s after drop").unwrap();
}
