//! Per-op schema hashes: a wire-3 caller whose whole schema differs is let in op by op.
//! The op whose types changed is refused with `SchemaMismatch`; the unchanged op works on the same connection; a
//! caller without an op table (wire 2) still gets the whole-schema refusal.
use ce_wire::{Caller, Client, Refusal, Server, WireError};

mod v1 {
    ce_wire::api! {
        api T = "perop.test", version 1;
        types {
            pub struct Item { pub name: String }
            pub struct List { pub items: Vec<Item> }
        }
        ops {
            1 => Items(()) -> List, needs "t.read";
            2 => Ping(u32) -> u32, needs "t.read";
        }
    }
}
mod v2 {
    ce_wire::api! {
        api T = "perop.test", version 2;
        types {
            pub struct Item { pub name: String, pub size: u64 }
            pub struct List { pub items: Vec<Item> }
            pub struct Extra { pub x: u8 }
        }
        ops {
            1 => Items(()) -> List, needs "t.read";
            2 => Ping(u32) -> u32, needs "t.read";
            3 => More(()) -> Extra, needs "t.read";
        }
    }
}

fn caller() -> Result<Caller, String> { Ok(Caller { name: "t".into(), rights: vec!["t.read".into()] }) }

async fn serve_v2() -> std::net::SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let s = Server::<v2::T>::new(|_| caller())
        .on::<v2::Items, _, _>(|_: (), _| async move { Ok(v2::List { items: vec![v2::Item { name: "a".into(), size: 1 }] }) })
        .on::<v2::Ping, _, _>(|n: u32, _| async move { Ok(n + 1) })
        .on::<v2::More, _, _>(|_: (), _| async move { Ok(v2::Extra { x: 1 }) });
    tokio::spawn(s.serve(l));
    a
}

#[test]
fn hashes() {
    assert_ne!(<v1::T as ce_wire::Api>::SCHEMA, <v2::T as ce_wire::Api>::SCHEMA);
    assert_ne!(ce_wire::op_hash::<v1::Items>(), ce_wire::op_hash::<v2::Items>());
    assert_eq!(ce_wire::op_hash::<v1::Ping>(), ce_wire::op_hash::<v2::Ping>());
}

#[tokio::test]
async fn older_caller_keeps_its_unchanged_ops() {
    let a = serve_v2().await;
    let c = Client::<v1::T>::connect(a, vec![]).await.expect("a wire-3 caller is let in op by op");
    assert_eq!(c.call::<v1::Ping>(&41).await.unwrap(), 42);
    match c.call::<v1::Items>(&()).await {
        Err(WireError::Refused(Refusal::SchemaMismatch { op: 1, op_name, ours, theirs, .. })) => {
            assert_eq!(op_name, "Items");
            assert_eq!((ours, theirs), (ce_wire::op_hash::<v2::Items>(), ce_wire::op_hash::<v1::Items>()));
        }
        r => panic!("want SchemaMismatch for Items, got {r:?}"),
    }
    // the connection is still good after the refusal
    assert_eq!(c.call::<v1::Ping>(&1).await.unwrap(), 2);
}

#[tokio::test]
async fn a_caller_without_an_op_table_gets_the_whole_schema_refusal() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let a = serve_v2().await;
    let mut s = tokio::net::TcpStream::connect(a).await.unwrap();
    let h = ce_wire::Hello { api: "perop.test".into(), version: 1, schema: <v1::T as ce_wire::Api>::SCHEMA, token: vec![], spawn: false };
    let p = ce_wire::hello_payload(&h, std::time::Duration::from_secs(1)).unwrap();
    s.write_all(&ce_wire::frame(ce_wire::Kind::Hello, 0, 0, &p)).await.unwrap();
    let mut hb = [0u8; ce_wire::HEADER];
    s.read_exact(&mut hb).await.unwrap();
    let hd = ce_wire::Header::decode(&hb).unwrap();
    let mut body = vec![0u8; hd.len as usize];
    s.read_exact(&mut body).await.unwrap();
    assert!(matches!(ce_wire::split_answer(&body).unwrap().0, Refusal::Schema { .. }));
}

#[tokio::test]
async fn same_schema_answer_carries_the_server_table() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let a = serve_v2().await;
    let mut s = tokio::net::TcpStream::connect(a).await.unwrap();
    let h = ce_wire::Hello { api: "perop.test".into(), version: 2, schema: <v2::T as ce_wire::Api>::SCHEMA, token: vec![], spawn: false };
    let p = ce_wire::hello_payload_ops(&h, std::time::Duration::from_secs(1), &ce_wire::op_hashes::<v2::T>()).unwrap();
    s.write_all(&ce_wire::frame(ce_wire::Kind::Hello, 0, 0, &p)).await.unwrap();
    let mut hb = [0u8; ce_wire::HEADER];
    s.read_exact(&mut hb).await.unwrap();
    let mut body = vec![0u8; ce_wire::Header::decode(&hb).unwrap().len as usize];
    s.read_exact(&mut body).await.unwrap();
    let (r, ops) = ce_wire::split_answer(&body).unwrap();
    assert!(matches!(r, Refusal::Ok { .. }));
    assert_eq!(ops, ce_wire::op_hashes::<v2::T>());
}

#[cfg(feature = "blocking")]
#[test]
fn blocking_server_checks_op_by_op_too() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    let s = ce_wire::blocking::Server::<v2::T>::new(|_| caller())
        .on::<v2::Items, _>(|_: (), _| Ok(v2::List { items: vec![] }))
        .on::<v2::Ping, _>(|n: u32, _| Ok(n + 1));
    std::thread::spawn(move || s.serve(l));
    let c = ce_wire::blocking::Client::<v1::T>::connect(a, vec![]).unwrap();
    assert_eq!(c.call::<v1::Ping>(&9).unwrap(), 10);
    assert!(matches!(c.call::<v1::Items>(&()), Err(WireError::Refused(Refusal::SchemaMismatch { op: 1, .. }))));
}
