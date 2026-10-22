//! blocking::Server::audit sees every answered op request like the tokio hook: ok with caller and grant, refused
//! with its refusal, recorded after the reply.
use ce_wire::{blocking, CallRecord, Caller, WireError};
use std::sync::{Arc, Mutex};

mod t {
    ce_wire::api! {
        api T = "example.test.audit-blocking", version 1;
        types { pub struct N { pub n: u32 } }
        ops { 1 => Echo(N) -> N, needs "t.read"; 2 => Wipe(()) -> (), needs "t.admin"; }
    }
}
use t::*;

#[test]
fn blocking_hook_sees_ok_and_refused() {
    let seen: Arc<Mutex<Vec<CallRecord>>> = Arc::default();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    let s2 = seen.clone();
    let s = blocking::Server::<T>::new(|_| Ok(Caller { name: "abc".into(), rights: vec!["t.read".into(), "grant:0123456789abcdef".into()] }))
        .on::<Echo, _>(|n: N, _| Ok(n))
        .on::<Wipe, _>(|_, _| Ok(()))
        .audit(move |c| s2.lock().unwrap().push(c.clone()));
    std::thread::spawn(move || s.serve(l));
    let c = blocking::Client::<T>::connect(a, vec![]).unwrap();
    assert_eq!(c.call::<Echo>(&N { n: 7 }).unwrap(), N { n: 7 });
    assert!(matches!(c.call::<Wipe>(&()), Err(WireError::Refused(_))));
    // one more call on the same connection: the hook for the previous request has run by the time it answers
    assert_eq!(c.call::<Echo>(&N { n: 8 }).unwrap(), N { n: 8 });
    for _ in 0..50 {
        if seen.lock().unwrap().len() == 3 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let v = seen.lock().unwrap().clone();
    assert_eq!(v.len(), 3);
    let e = &v[0];
    assert_eq!((e.api, e.op_name, e.right, e.caller.as_str(), e.grant.as_str(), e.ok), ("example.test.audit-blocking", "Echo", "t.read", "abc", "0123456789abcdef", true));
    assert!(!v[1].ok && v[1].refusal.contains("t.admin"), "{:?}", v[1]);
}
