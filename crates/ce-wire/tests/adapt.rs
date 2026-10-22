//! Typed adapters (src/adapt.rs): a v2 server answers a v1 caller through `Older`.
use ce_wire::adapt::Older;
use ce_wire::{AdaptError, Caller, Client, Refusal, Server, WireError};

mod v1 {
    ce_wire::api! {
        api Grant = "adapt.test", version 1;
        types {
            pub struct GrantReq { pub person: String }
            pub struct Granted { pub fragment: String, pub not_after: u32 }
            pub enum GrantError { Refused(String), Failed(String) }
        }
        ops {
            1 => GrantOp(GrantReq) -> Result<Granted, GrantError>, needs "t.grant";
            2 => Ping(()) -> u32, needs "t.grant";
            3 => Old(()) -> bool, needs "t.grant";
        }
    }
}
mod v2 {
    ce_wire::api! {
        api Grant = "adapt.test", version 2;
        types {
            pub struct GrantReq { pub person: String, pub ttl_s: Option<u32> }
            pub struct Granted { pub fragment: String, pub ends_at: u64 }
            pub enum GrantError { Refused(String), Failed(String), Busy }
        }
        ops {
            1 => GrantOp(GrantReq) -> Result<Granted, GrantError>, needs "t.grant";
            2 => Ping(()) -> u32, needs "t.grant";
        }
    }
}

fn err_down(e: v2::GrantError) -> Result<v1::GrantError, AdaptError> {
    Ok(match e {
        v2::GrantError::Refused(s) => v1::GrantError::Refused(s),
        v2::GrantError::Failed(s) => v1::GrantError::Failed(s),
        v2::GrantError::Busy => return Err(AdaptError::NoVariant { field: "GrantError".into(), variant: "Busy".into() }),
    })
}

async fn serve_v2() -> std::net::SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let old = Older::of::<v1::Grant>()
        .op::<v1::GrantOp, v2::GrantOp>(
            |r| Ok(v2::GrantReq { person: r.person, ttl_s: None }),
            |r| match r {
                Ok(g) => Ok(Ok(v1::Granted {
                    fragment: g.fragment,
                    not_after: u32::try_from(g.ends_at).map_err(|_| AdaptError::Narrow { field: "Granted.ends_at".into(), value: g.ends_at.to_string() })?,
                })),
                Err(e) => Ok(Err(err_down(e)?)),
            },
        )
        .same::<v1::Ping, v2::Ping>()
        .gone::<v1::Old>();
    let s = Server::<v2::Grant>::new(|_| Ok(Caller { name: "t".into(), rights: vec!["t.grant".into()] }))
        .older(old)
        .on::<v2::GrantOp, _, _>(|r: v2::GrantReq, _| async move {
            Ok(match r.person.as_str() {
                "big" => Ok(v2::Granted { fragment: "f".into(), ends_at: u64::MAX }),
                "busy" => Err(v2::GrantError::Busy),
                "no" => Err(v2::GrantError::Refused("not listed".into())),
                p => Ok(v2::Granted { fragment: format!("{p}:{}", r.ttl_s.unwrap_or(3600)), ends_at: 1_800_000_000 }),
            })
        })
        .on::<v2::Ping, _, _>(|_: (), _| async move { Ok(7u32) });
    tokio::spawn(s.serve(l));
    a
}

#[tokio::test]
async fn v1_caller_is_answered_by_v2_server() {
    let a = serve_v2().await;
    let c = Client::<v1::Grant>::connect(a, vec![]).await.unwrap();
    let g = c.call::<v1::GrantOp>(&v1::GrantReq { person: "alice".into() }).await.unwrap().unwrap();
    assert_eq!((g.fragment.as_str(), g.not_after), ("alice:3600", 1_800_000_000));
    assert!(matches!(c.call::<v1::GrantOp>(&v1::GrantReq { person: "no".into() }).await.unwrap(), Err(v1::GrantError::Refused(_))));
    assert_eq!(c.call::<v1::Ping>(&()).await.unwrap(), 7);
    // a current caller on the same server still works
    let c2 = Client::<v2::Grant>::connect(a, vec![]).await.unwrap();
    assert_eq!(c2.call::<v2::GrantOp>(&v2::GrantReq { person: "x".into(), ttl_s: Some(60) }).await.unwrap().unwrap().fragment, "x:60");
}

#[tokio::test]
async fn typed_refusals_name_the_op_and_keep_the_connection() {
    let a = serve_v2().await;
    let c = Client::<v1::Grant>::connect(a, vec![]).await.unwrap();
    let r = c.call::<v1::GrantOp>(&v1::GrantReq { person: "big".into() }).await;
    match r {
        Err(WireError::Refused(Refusal::Adapt { op: 1, op_name, ours: 2, theirs: 1, why: AdaptError::Narrow { field, .. }, .. })) => {
            assert_eq!((op_name.as_str(), field.as_str()), ("GrantOp", "Granted.ends_at"))
        }
        other => panic!("{other:?}"),
    }
    let r = c.call::<v1::GrantOp>(&v1::GrantReq { person: "busy".into() }).await;
    assert!(matches!(r, Err(WireError::Refused(Refusal::Adapt { why: AdaptError::NoVariant { .. }, .. }))), "{r:?}");
    let r = c.call::<v1::Old>(&()).await;
    assert!(matches!(&r, Err(WireError::Refused(Refusal::Adapt { op: 3, why: AdaptError::NoPath, .. }))), "{r:?}");
    if let Err(WireError::Refused(Refusal::Adapt { op_name, .. })) = r {
        assert_eq!(op_name, "Old");
    }
    // the connection is still good after three refusals
    assert_eq!(c.call::<v1::Ping>(&()).await.unwrap(), 7);
}

#[tokio::test]
async fn unknown_schema_is_still_refused_at_hello() {
    mod v0 {
        ce_wire::api! {
            api Grant = "adapt.test", version 0;
            types { pub struct X { pub a: u8 } }
            ops { 1 => GrantOp(X) -> X, needs "t.grant"; }
        }
    }
    let a = serve_v2().await;
    assert!(matches!(Client::<v0::Grant>::connect(a, vec![]).await, Err(WireError::Refused(Refusal::Schema { .. }))));
}

#[test]
fn blocking_server_answers_v1_caller() {
    use ce_wire::blocking;
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    let s = blocking::Server::<v2::Grant>::new(|_| Ok(Caller { name: "t".into(), rights: vec!["t.grant".into()] }))
        .older(Older::of::<v1::Grant>().same::<v1::Ping, v2::Ping>().op::<v1::GrantOp, v2::GrantOp>(
            |r| Ok(v2::GrantReq { person: r.person, ttl_s: None }),
            |r| r.map(|g| v1::Granted { fragment: g.fragment, not_after: g.ends_at as u32 }).map_err(|_| AdaptError::Missing { field: "err".into() }).map(Ok),
        ))
        .on::<v2::Ping, _>(|_, _| Ok(9))
        .on::<v2::GrantOp, _>(|r, _| Ok(Ok(v2::Granted { fragment: r.person, ends_at: 5 })));
    std::thread::spawn(move || s.serve(l));
    let c = blocking::Client::<v1::Grant>::connect(a, vec![]).unwrap();
    assert_eq!(c.call::<v1::Ping>(&()).unwrap(), 9);
    let g = c.call::<v1::GrantOp>(&v1::GrantReq { person: "p".into() }).unwrap().unwrap();
    assert_eq!((g.fragment.as_str(), g.not_after), ("p", 5));
    assert!(matches!(c.call::<v1::Old>(&()), Err(WireError::Refused(Refusal::Adapt { why: AdaptError::NoPath, .. }))));
}
