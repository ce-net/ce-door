//! The blocking (std thread) side speaks the same wire as the tokio side.
use ce_wire::{blocking, Caller, Refusal, WireError};
use std::time::Duration;

mod bus {
    ce_wire::api! {
        api Bus = "example.test.bus", version 1;
        types { pub struct Goal { pub id: u8, pub counts: i16 } pub struct Ack { pub id: u8, pub counts: i16 } pub struct Watch { pub n: u32 } }
        ops { 1 => SetGoal(Goal) -> Ack, needs "bus.goal"; 2 => Reboot(()) -> (), needs "bus.admin"; }
        streams { 3 => Live(Watch) -> stream Ack, needs "bus.read"; }
    }
}
use bus::*;

fn server() -> std::net::SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    let s = blocking::Server::<Bus>::new(|h| match h.token.as_slice() {
        b"ok" => Ok(Caller { name: "t".into(), rights: vec!["bus.goal".into(), "bus.read".into()] }),
        _ => Err("no token".into()),
    })
    .on::<SetGoal, _>(|g: Goal, _| Ok(Ack { id: g.id, counts: g.counts * 2 }))
    .on::<Reboot, _>(|_, _| Ok(()))
    .stream::<Live, _>(|w: Watch, _, sink| {
        for i in 0..w.n {
            sink.send(&Ack { id: i as u8, counts: 0 }).map_err(|e| e.to_string())?;
        }
        Ok(())
    });
    std::thread::spawn(move || s.serve(l));
    a
}

#[test]
fn blocking_client_and_server() {
    let a = server();
    let c = blocking::Client::<Bus>::connect(a, b"ok".to_vec()).unwrap();
    assert_eq!(c.call::<SetGoal>(&Goal { id: 3, counts: -21 }).unwrap(), Ack { id: 3, counts: -42 });
    assert_eq!(c.call::<Reboot>(&()), Err(WireError::Refused(Refusal::Right("bus.admin".into()))));
    assert!(matches!(blocking::Client::<Bus>::connect(a, b"bad".to_vec()), Err(WireError::Refused(Refusal::Gate(_)))));
}

#[tokio::test(flavor = "multi_thread")]
async fn tokio_client_to_blocking_server() {
    let a = server();
    let c = ce_wire::Client::<Bus>::connect(a, b"ok".to_vec()).await.unwrap();
    assert_eq!(c.call::<SetGoal>(&Goal { id: 1, counts: 5 }).await.unwrap(), Ack { id: 1, counts: 10 });
    let mut s = c.subscribe::<Live>(&Watch { n: 3 }).unwrap();
    let mut got = vec![];
    while let Some(x) = s.next().await {
        got.push(x.unwrap().id);
    }
    assert_eq!(got, vec![0, 1, 2]);
}

#[test]
fn blocking_client_to_tokio_server() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let l = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
    let a = l.local_addr().unwrap();
    let s = ce_wire::Server::<Bus>::new(|_| Ok(Caller { name: "t".into(), rights: vec!["bus.goal".into()] }))
        .on::<SetGoal, _, _>(|g: Goal, _| async move { Ok(Ack { id: g.id, counts: g.counts + 1 }) });
    rt.spawn(s.serve(l));
    let c = blocking::Client::<Bus>::connect(a, vec![]).unwrap();
    assert_eq!(c.call::<SetGoal>(&Goal { id: 9, counts: 1 }).unwrap(), Ack { id: 9, counts: 2 });
}

#[test]
fn blocking_datagrams_drop_stale_and_strangers() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    let s = blocking::Server::<Bus>::new(|_| Ok(Caller { name: "t".into(), rights: vec!["bus.goal".into()] }));
    let sessions = s.sessions();
    std::thread::spawn(move || s.serve(l));
    let c = blocking::Client::<Bus>::connect(a, vec![]).unwrap();
    let mut rx = blocking::DatagramSocket::<Bus>::bind("127.0.0.1:0", Some(sessions)).unwrap();
    rx.socket().set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let to = rx.local_addr().unwrap();
    let tx = blocking::DatagramSocket::<Bus>::bind("127.0.0.1:0", None).unwrap();
    tx.send::<SetGoal>(to, 12345, &Goal { id: 0, counts: 0 }).unwrap(); // stranger: unknown session
    tx.send::<SetGoal>(to, c.session(), &Goal { id: 1, counts: 7 }).unwrap();
    let rights = ce_wire::rights![SetGoal];
    let d = rx.recv(&rights).unwrap();
    assert_eq!(d.decode::<SetGoal>(), Some(Goal { id: 1, counts: 7 }));
    assert!(matches!(rx.recv(&rights), Err(WireError::Timeout)));
}

#[test]
fn blocking_by_name_through_the_door() {
    let dir = std::env::temp_dir().join(format!("ce-door-btest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    std::env::set_var("CE_DOOR_PORT", port.to_string());
    std::env::set_var("CE_DOOR_SOCK", dir.join("door.sock"));
    std::env::set_var("CE_WIRE_PEERS", "");
    std::env::set_var("CE_WIRE_APPS", &dir);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.spawn(ce_wire::run_door(vec![([127, 0, 0, 1], port).into()], dir.join("door.sock")));
    std::thread::sleep(Duration::from_millis(50));
    assert!(matches!(blocking::Client::<Bus>::by_name(vec![]), Err(WireError::Unreachable(u)) if u.cause.contains("NoCell")));
    let s = ce_wire::Server::<Bus>::new(|_| Ok(Caller { name: "t".into(), rights: vec!["bus.goal".into()] }))
        .on::<SetGoal, _, _>(|g: Goal, _| async move { Ok(Ack { id: g.id, counts: g.counts - 1 }) });
    rt.spawn(s.serve_door());
    std::thread::sleep(Duration::from_millis(50));
    let c = blocking::Client::<Bus>::by_name(vec![]).unwrap();
    assert_eq!(c.call::<SetGoal>(&Goal { id: 4, counts: 4 }).unwrap(), Ack { id: 4, counts: 3 });
}

#[cfg(feature = "blocking-door")]
#[test]
fn blocking_cell_behind_the_door() {
    let dir = std::env::temp_dir().join(format!("ce-door-bdoor-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let sock = dir.join("door.sock");
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.spawn(ce_wire::run_door(vec![([127, 0, 0, 1], port).into()], sock.clone()));
    std::thread::sleep(Duration::from_millis(50));
    let s = blocking::Server::<Bus>::new(|_| Ok(Caller { name: "t".into(), rights: vec!["bus.goal".into()] }))
        .on::<SetGoal, _>(|g: Goal, _| Ok(Ack { id: g.id, counts: g.counts + 100 }));
    std::thread::spawn(move || s.serve_door_at(&sock));
    std::thread::sleep(Duration::from_millis(50));
    let c = blocking::Client::<Bus>::connect(("127.0.0.1", port), vec![]).unwrap();
    assert_eq!(c.call::<SetGoal>(&Goal { id: 2, counts: 1 }).unwrap(), Ack { id: 2, counts: 101 });
}
