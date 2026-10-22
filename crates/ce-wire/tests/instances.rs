//! Instance names: many cells serve one api (`obs.source#wx.metar`, `obs.source#wx.smhi`). A Hello for an instance
//! reaches only it; a Hello for the bare api reaches any; an instance miss on the last (spawn) step falls back to the
//! bare api without schema-drift; a Hello for `<api>#*` lists the instances; an old unnamed cell is unchanged.
//! One door per test binary (env is process-wide), so everything is one test.
use ce_wire::{Caller, Client, Refusal, Server, WireError};

mod inst {
    ce_wire::api! {
        api Src = "example.test.inst", version 1;
        types { pub struct Who { pub name: String } }
        ops { 1 => Name(()) -> Who, needs "t.read"; }
    }
}
mod old {
    ce_wire::api! {
        api Old = "example.test.inst-old", version 1;
        types { pub struct N { pub x: u32 } }
        ops { 1 => Inc(N) -> N, needs "t.inc"; }
    }
}

fn src(name: &'static str) -> Server<inst::Src> {
    Server::<inst::Src>::new(|_| Ok(Caller { name: "t".into(), rights: vec!["t.read".into()] }))
        .on::<inst::Name, _, _>(move |_: (), _| async move { Ok(inst::Who { name: name.into() }) })
}

async fn name_of(c: &Client<inst::Src>) -> String {
    c.call::<inst::Name>(&()).await.unwrap().name
}

#[tokio::test]
async fn instances_of_one_api_share_a_door() {
    let dir = std::env::temp_dir().join(format!("ce-door-inst-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    for (d, toml) in [
        ("a", "[cell]\napi = \"example.test.inst\"\nname = \"a\"\nspawn = [\"true\"]\n"),
        ("bare", "[cell]\napi = \"example.test.inst\"\nspawn = [\"true\"]\n"),
        ("old", "[cell]\napi = \"example.test.inst-old\"\nspawn = [\"true\"]\n"),
    ] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
        std::fs::write(dir.join(d).join("cell.toml"), toml).unwrap();
    }
    let port = { std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() };
    std::env::set_var("CE_DOOR_PORT", port.to_string());
    std::env::set_var("CE_DOOR_SOCK", dir.join("door.sock"));
    std::env::set_var("CE_WIRE_PEERS", "");
    std::env::set_var("CE_WIRE_APPS", &dir);
    std::env::set_var("CE_NODE", "127.0.0.1:1"); // no ce node: adverts and DHT finds fail fast

    // cell.toml `name` picks the instance's manifest; a bare api prefers the unnamed one.
    assert_eq!(ce_wire::find_manifest("example.test.inst#a"), Some(dir.join("a/cell.toml")));
    assert_eq!(ce_wire::find_manifest("example.test.inst"), Some(dir.join("bare/cell.toml")));
    assert_eq!(ce_wire::find_manifest("example.test.inst#c"), None);
    assert_eq!(ce_wire::manifest_key(&std::fs::read_to_string(dir.join("a/cell.toml")).unwrap()), "example.test.inst#a");

    tokio::spawn(ce_wire::run_door(vec![([127, 0, 0, 1], port).into()], dir.join("door.sock")));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let (_, events) = ce_wire::watch();

    tokio::spawn(src("a").serve_door_as("a"));
    tokio::spawn(src("b").serve_door_as("b"));
    // an old cell, no instance: registers and answers exactly as before
    tokio::spawn(
        Server::<old::Old>::new(|_| Ok(Caller { name: "t".into(), rights: vec!["t.inc".into()] }))
            .on::<old::Inc, _, _>(|n: old::N, _| async move { Ok(old::N { x: n.x + 1 }) })
            .serve_door(),
    );
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    // an invalid instance name is refused before it registers
    assert!(src("x").serve_door_as("bad name").await.is_err());

    // by_instance reaches each instance, every time
    for _ in 0..4 {
        assert_eq!(name_of(&Client::<inst::Src>::by_instance("a", vec![]).await.unwrap()).await, "a");
        assert_eq!(name_of(&Client::<inst::Src>::by_instance("b", vec![]).await.unwrap()).await, "b");
    }
    // the bare api reaches either
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..8 {
        seen.insert(name_of(&Client::<inst::Src>::by_name(vec![]).await.unwrap()).await);
    }
    assert_eq!(seen.into_iter().collect::<Vec<_>>(), vec!["a", "b"]);

    // the old cell is unchanged
    let o = Client::<old::Old>::by_name(vec![]).await.unwrap();
    assert_eq!(o.call::<old::Inc>(&old::N { x: 1 }).await.unwrap().x, 2);

    // "which instances of this api run here", over TCP (works from any mesh peer)
    let local = format!("127.0.0.1:{port}");
    assert_eq!(ce_wire::instances_at(&local, "example.test.inst").await.unwrap(), vec!["example.test.inst#a", "example.test.inst#b"]);
    assert_eq!(ce_wire::instances_at(&local, "example.test.inst-old").await.unwrap(), vec!["example.test.inst-old"]);
    assert_eq!(ce_wire::instances_at(&local, "example.test.none").await.unwrap(), Vec::<String>::new());

    // an instance miss without spawn is refused, so a caller goes on to the machine that runs it
    match Client::<inst::Src>::connect_instance(&local, "c", vec![]).await {
        Err(WireError::Refused(Refusal::NoCell(m))) => assert!(m.contains("#c"), "{m}"),
        r => panic!("{:?}", r.map(|_| ())),
    }
    // ...and by_instance's last step (the spawning Hello) falls back to the bare api: no manifest for #c here
    let n = name_of(&Client::<inst::Src>::by_instance("c", vec![]).await.unwrap()).await;
    assert!(n == "a" || n == "b", "{n}");

    // a Hello for another api's instance is refused by the cell's own check (the door routes by name, the cell checks)
    assert!(Client::<inst::Src>::connect_opts_as(&local, "example.test.inst-old#a", vec![], false, ce_wire::DEADLINE).await.is_err());

    // LIST shows the full names
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut u = tokio::net::UnixStream::connect(dir.join("door.sock")).await.unwrap();
        u.write_all(b"LIST\n").await.unwrap();
        let mut out = String::new();
        u.read_to_string(&mut out).await.unwrap();
        assert!(out.contains("example.test.inst#a 1") && out.contains("example.test.inst#b 1") && out.contains("example.test.inst-old 1"), "{out}");
    }
    // STOP of one instance leaves the other
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut u = tokio::net::UnixStream::connect(dir.join("door.sock")).await.unwrap();
        u.write_all(b"STOP example.test.inst#a\n").await.unwrap();
        let mut out = String::new();
        u.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("stopped 1"), "{out}");
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(ce_wire::instances_at(&local, "example.test.inst").await.unwrap(), vec!["example.test.inst#b"]);

    // the miss was an instance-miss event, never schema drift
    let mut evs = vec![];
    while let Ok(e) = events.try_recv() {
        evs.push(e);
    }
    assert!(evs.iter().any(|e| e.contains(" instance-miss example.test.inst#c ")), "{evs:?}");
    assert!(!evs.iter().any(|e| e.contains("schema-drift")), "{evs:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
