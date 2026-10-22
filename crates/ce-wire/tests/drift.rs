//! Schema drift at the door: two builds of one api with different schemas. The old one is
//! placed; a caller built against the new one gets `SchemaAt{update:"checking"}`, retries once, and the door builds
//! the cell's upstream in a clean worktree, swaps it in once it registers, and hands the held Hello to it.
//! The "builds" are this test binary run as `drift_cell_v1` / `drift_cell_v2` (ignored tests), named by cell.toml.
use ce_wire::{Caller, Client, Refusal, Server, WireError};
use std::path::Path;
use std::process::Command;

mod v1 {
    ce_wire::api! {
        api Cell = "drift.test", version 1;
        types { pub struct N { pub x: u32 } }
        ops { 1 => Inc(N) -> N, needs "drift.inc"; }
    }
}
mod v2 {
    ce_wire::api! {
        api Cell = "drift.test", version 1;
        types { pub struct N { pub x: u64 } }
        ops { 1 => Inc(N) -> N, needs "drift.inc"; }
    }
}

#[tokio::test]
#[ignore = "a cell process the drift test spawns"]
async fn drift_cell_v1() {
    let s = Server::<v1::Cell>::new(|_| Ok(Caller { name: "t".into(), rights: vec!["drift.inc".into()] }))
        .on::<v1::Inc, _, _>(|n: v1::N, _| async move { Ok(v1::N { x: n.x + 1 }) });
    let _ = s.serve_door().await;
}

#[tokio::test]
#[ignore = "a cell process the drift test spawns"]
async fn drift_cell_v2() {
    let s = Server::<v2::Cell>::new(|_| Ok(Caller { name: "t".into(), rights: vec!["drift.inc".into()] }))
        .on::<v2::Inc, _, _>(|n: v2::N, _| async move { Ok(v2::N { x: n.x + 2 }) });
    let _ = s.serve_door().await;
}

fn git(dir: &Path, args: &[&str]) {
    let o = Command::new("git").arg("-C").arg(dir).args(args).output().unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
}

fn commit(dir: &Path, which: &str) {
    let exe = std::env::current_exe().unwrap().display().to_string();
    std::fs::write(
        dir.join("cell.toml"),
        format!("[cell]\napi = \"drift.test\"\nspawn = [\"{exe}\", \"--exact\", \"drift_cell_{which}\", \"--ignored\", \"--nocapture\"]\n"),
    )
    .unwrap();
    git(dir, &["add", "cell.toml"]);
    git(dir, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", which]);
}

async fn door_line(sock: &Path, line: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::UnixStream::connect(sock).await.unwrap();
    s.write_all(format!("{line}\n").as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    out
}

#[tokio::test]
async fn caller_with_the_new_schema_gets_the_swap_and_one_success() {
    let root = std::env::temp_dir().join(format!("ce-drift-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (up, apps, home) = (root.join("up.git"), root.join("apps"), root.join("home"));
    for d in [&apps, &home] {
        std::fs::create_dir_all(d).unwrap();
    }
    git(&root, &["init", "-q", "--bare", "up.git"]);
    // the door's checkout: v1, pushed, clean
    let co = apps.join("drift-cell");
    git(&apps, &["clone", "-q", up.to_str().unwrap(), "drift-cell"]);
    commit(&co, "v1");
    git(&co, &["push", "-q", "-u", "origin", "HEAD"]);
    git(&co, &["fetch", "-q"]);
    // someone pushes v2 upstream; the door's checkout is now behind
    let other = root.join("other");
    git(&root, &["clone", "-q", up.to_str().unwrap(), "other"]);
    commit(&other, "v2");
    git(&other, &["push", "-q", "origin", "HEAD"]);

    let sock = root.join("door.sock");
    let port = { std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() };
    std::env::set_var("CE_DOOR_PORT", port.to_string());
    std::env::set_var("CE_DOOR_SOCK", &sock);
    std::env::set_var("CE_WIRE_PEERS", "");
    std::env::set_var("CE_WIRE_APPS", &apps);
    std::env::set_var("CE_DOOR_ROOM", "none"); // no host-room booking in a test
    std::env::set_var("HOME", &home); // the build worktree lands in home/.cache/ce-door
    tokio::spawn(ce_wire::run_door(vec![([127, 0, 0, 1], port).into()], sock.clone()));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // the old build is placed and answers its own callers
    let placed = door_line(&sock, "PLACE drift.test").await;
    assert!(placed.contains("drift.test"), "{placed}");
    let door = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let mut c1 = None;
    for _ in 0..100 {
        if let Ok(c) = Client::<v1::Cell>::connect(door, vec![]).await {
            c1 = Some(c);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(c1.expect("v1 never registered").call::<v1::Inc>(&v1::N { x: 1 }).await.unwrap().x, 2);

    // a caller built against v2: one refusal (logged, checking), one waiting retry, then the swapped-in v2 answers
    let c2 = Client::<v2::Cell>::connect_opts(door, vec![], false, ce_wire::DEADLINE).await.expect("v2 after the swap");
    assert_eq!(c2.call::<v2::Inc>(&v2::N { x: 1 }).await.unwrap().x, 3);

    // only v2 runs now, built from the upstream worktree, never from the door's checkout. The held Hello is handed
    // over as soon as v2 registers; the door stops v1 on its next register poll (200 ms), so wait for that, bounded.
    let want = format!("drift.test 1 {:016x}", <v2::Cell as ce_wire::Api>::SCHEMA);
    let mut list = String::new();
    for _ in 0..100 {
        list = door_line(&sock, "LIST schema").await;
        if list.lines().any(|l| l == want) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(list.lines().any(|l| l == want), "want {want}: {list}");
    let b = std::fs::read_dir(home.join(".cache/ce-door/builds/drift.test")).unwrap().next().unwrap().unwrap().path();
    assert!(b.join(".ce-door-built").is_file(), "a finished build is marked, so a restarted door reuses it");
    assert!(std::fs::read_to_string(co.join("cell.toml")).unwrap().contains("drift_cell_v1"), "the checkout was touched");

    // a v1 caller now: the finished check answers for 10 min, so no second update and no waiting retry
    match Client::<v1::Cell>::connect(door, vec![]).await {
        Err(WireError::Refused(Refusal::SchemaAt { update, .. })) => assert_eq!(update, "rate-limited"),
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("v1 still served"),
    }
    let _ = door_line(&sock, "STOP drift.test").await;
    let _ = std::fs::remove_dir_all(&root);
}
