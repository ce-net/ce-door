//! `deadline_ms N` in api!: an op that takes 1.5 s answers when it declares 3 s and times out at the 1 s default, on the
//! tokio client and the blocking one; the schema hash does not change (the deadline is not on the wire).
use ce_wire::{blocking, Api, Caller, Client, Op, Server, WireError};
use std::time::Duration;

mod slow {
    ce_wire::api! {
        api Slow = "example.test.slow", version 1;
        types { pub struct N { pub n: u8 } }
        ops { 1 => Quick(N) -> N, needs "t:x"; 2 => Patient(N) -> N, needs "t:x", deadline_ms 3000; }
    }
}
mod same {
    ce_wire::api! {
        api Slow = "example.test.slow", version 1;
        types { pub struct N { pub n: u8 } }
        ops { 1 => Quick(N) -> N, needs "t:x"; 2 => Patient(N) -> N, needs "t:x"; }
    }
}
use slow::*;

const WAIT: Duration = Duration::from_millis(1500);

#[test]
fn declared_and_hashed() {
    assert_eq!(Quick::DEADLINE_MS, None);
    assert_eq!(Patient::DEADLINE_MS, Some(3000));
    assert_eq!(Slow::SCHEMA, same::Slow::SCHEMA);
    assert_eq!(ce_wire::op_deadline::<Patient>(Duration::from_secs(1)), Duration::from_secs(3));
    assert_eq!(ce_wire::op_deadline::<Patient>(Duration::from_secs(9)), Duration::from_secs(9), "a longer client deadline wins");
    assert_eq!(ce_wire::op_deadline::<Quick>(Duration::from_secs(1)), Duration::from_secs(1));
}

#[tokio::test]
async fn tokio_client_waits_the_op_deadline() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let s = Server::<Slow>::new(|_| Ok(Caller { name: "t".into(), rights: vec!["t:x".into()] }))
        .on::<Quick, _, _>(|n: N, _| async move {
            tokio::time::sleep(WAIT).await;
            Ok(n)
        })
        .on::<Patient, _, _>(|n: N, _| async move {
            tokio::time::sleep(WAIT).await;
            Ok(n)
        });
    tokio::spawn(s.serve(l));
    let c = Client::<Slow>::connect(a, vec![]).await.unwrap();
    assert_eq!(c.call::<Patient>(&N { n: 7 }).await.unwrap(), N { n: 7 });
    assert!(matches!(c.call::<Quick>(&N { n: 1 }).await, Err(WireError::Timeout)));
}

#[test]
fn blocking_client_waits_the_op_deadline() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    let s = blocking::Server::<Slow>::new(|_| Ok(Caller { name: "t".into(), rights: vec!["t:x".into()] }))
        .on::<Quick, _>(|n: N, _| {
            std::thread::sleep(WAIT);
            Ok(n)
        })
        .on::<Patient, _>(|n: N, _| {
            std::thread::sleep(WAIT);
            Ok(n)
        });
    std::thread::spawn(move || s.serve(l));
    let c = blocking::Client::<Slow>::connect(a, vec![]).unwrap();
    assert_eq!(c.call::<Patient>(&N { n: 7 }).unwrap(), N { n: 7 });
    // the widened timeout was put back: the next slow op without a deadline times out at 1 s
    assert!(matches!(c.call::<Quick>(&N { n: 1 }), Err(WireError::Timeout)));
}
