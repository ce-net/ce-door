//! Server::audit sees every answered op request: the allowed one with ok, the refused one with its refusal, the
//! caller name and the grant from the `grant:` right; a server without the hook behaves as before.
use ce_wire::{CallRecord, Caller, Client, Server, WireError};
use std::sync::{Arc, Mutex};

mod t {
    ce_wire::api! {
        api T = "example.test.audit", version 1;
        types { pub struct N { pub n: u32 } }
        ops { 1 => Echo(N) -> N, needs "t.read"; 2 => Wipe(()) -> (), needs "t.admin"; }
    }
}
use t::*;

#[tokio::test]
async fn hook_sees_ok_and_refused() {
    let seen: Arc<Mutex<Vec<CallRecord>>> = Arc::default();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let s2 = seen.clone();
    let s = Server::<T>::new(|_| Ok(Caller { name: "abc".into(), rights: vec!["t.read".into(), "grant:0123456789abcdef".into()] }))
        .on::<Echo, _, _>(|n: N, _| async move { Ok(n) })
        .on::<Wipe, _, _>(|_, _| async move { Ok(()) })
        .audit(move |c| s2.lock().unwrap().push(c.clone()));
    tokio::spawn(s.serve(l));
    let c = Client::<T>::connect(a, vec![]).await.unwrap();
    assert_eq!(c.call::<Echo>(&N { n: 7 }).await.unwrap(), N { n: 7 });
    assert!(matches!(c.call::<Wipe>(&()).await, Err(WireError::Refused(_))));
    // the record is written after the reply: give the task a moment
    for _ in 0..50 {
        if seen.lock().unwrap().len() == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let v = seen.lock().unwrap().clone();
    assert_eq!(v.len(), 2);
    let e = v.iter().find(|r| r.op == 1).unwrap();
    assert_eq!((e.api, e.op_name, e.right, e.caller.as_str(), e.grant.as_str(), e.ok), ("example.test.audit", "Echo", "t.read", "abc", "0123456789abcdef", true));
    let w = v.iter().find(|r| r.op == 2).unwrap();
    assert!(!w.ok && w.refusal.contains("t.admin"), "{w:?}");
}
