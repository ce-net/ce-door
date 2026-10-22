//! The door restarts a cell that ends by itself when its cell.toml has `[launch] restart_backoff_ms`, and leaves a
//! cell stopped with `ce-door stop-owner` (its owner) down. The cell is this test binary run as `restart_cell` (an ignored test).
use ce_wire::{Caller, Client, Server};
use std::path::Path;

mod c {
    ce_wire::api! {
        api Cell = "restart.test", version 1;
        types { pub struct P { pub pid: u32 } }
        ops { 1 => Pid(()) -> P, needs "r.x"; 2 => Die(()) -> (), needs "r.x"; }
    }
}
use c::*;

#[tokio::test]
#[ignore = "a cell process the restart test spawns"]
async fn restart_cell() {
    let s = Server::<Cell>::new(|_| Ok(Caller { name: "t".into(), rights: vec!["r.x".into()] }))
        .on::<Pid, _, _>(|_, _| async move { Ok(P { pid: std::process::id() }) })
        .on::<Die, _, _>(|_, _| async move {
            std::thread::spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(100));
                std::process::exit(3);
            });
            Ok(())
        });
    let _ = s.serve_door().await;
}

async fn door_line(sock: &Path, line: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::UnixStream::connect(sock).await.unwrap();
    s.write_all(format!("{line}\n").as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    out
}

/// The pid of the registered cell, waiting up to `ms` for one other than `not`.
async fn pid_within(door: std::net::SocketAddr, not: u32, ms: u64) -> Option<u32> {
    let t = std::time::Instant::now();
    while t.elapsed().as_millis() < ms as u128 {
        if let Ok(c) = Client::<Cell>::connect(door, vec![]).await {
            if let Ok(P { pid: p }) = c.call::<Pid>(&()).await {
                if p != not {
                    return Some(p);
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    None
}

async fn listed(sock: &Path) -> bool {
    door_line(sock, "LIST").await.lines().any(|l| l.starts_with("restart.test "))
}

#[test]
fn backoff_is_read_and_doubles() {
    let d = std::env::temp_dir().join(format!("ce-restart-unit-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let m = d.join("cell.toml");
    std::fs::write(&m, "[cell]\napi = \"x\"\n[launch]\nrestart_backoff_ms = [1000, 300000]\n").unwrap();
    assert_eq!(ce_wire::restart_backoff(&m), Some((1000, 300000)));
    std::fs::write(&m, "[cell]\napi = \"x\"\n").unwrap();
    assert_eq!(ce_wire::restart_backoff(&m), None);
    assert_eq!((0..11).map(|n| ce_wire::restart_wait(1000, 300000, n)).collect::<Vec<_>>(), [1000, 2000, 4000, 8000, 16000, 32000, 64000, 128000, 256000, 300000, 300000]);
}

#[tokio::test]
async fn a_cell_that_dies_comes_back_and_a_stopped_one_does_not() {
    let root = std::env::temp_dir().join(format!("ce-restart-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (apps, home) = (root.join("apps"), root.join("home"));
    std::fs::create_dir_all(apps.join("restart-cell")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let exe = std::env::current_exe().unwrap().display().to_string();
    std::fs::write(
        apps.join("restart-cell/cell.toml"),
        format!("[cell]\napi = \"restart.test\"\nowner = \"foreman/restart-owner\"  # who runs it\nspawn = [\"{exe}\", \"--exact\", \"restart_cell\", \"--ignored\", \"--nocapture\"]\n\n[launch]\nrestart_backoff_ms = [200, 1000]\n"),
    )
    .unwrap();
    let sock = root.join("door.sock");
    let port = { std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() };
    std::env::set_var("CE_DOOR_PORT", port.to_string());
    std::env::set_var("CE_DOOR_SOCK", &sock);
    std::env::set_var("CE_WIRE_PEERS", "");
    std::env::set_var("CE_WIRE_APPS", &apps);
    std::env::set_var("CE_DOOR_ROOM", "none");
    std::env::set_var("HOME", &home);
    tokio::spawn(ce_wire::run_door(vec![([127, 0, 0, 1], port).into()], sock.clone()));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let door = std::net::SocketAddr::from(([127, 0, 0, 1], port));

    assert!(door_line(&sock, "PLACE restart.test").await.contains("restart.test"));
    let p1 = pid_within(door, 0, 10_000).await.expect("the cell never registered");

    // a second copy of the same api, started outside the door while the first serves: refused, it ends, one is listed
    let mut dup = std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact", "restart_cell", "--ignored", "--nocapture"]).spawn().unwrap();
    let t = std::time::Instant::now();
    while dup.try_wait().unwrap().is_none() && t.elapsed().as_secs() < 10 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let ended = dup.try_wait().unwrap().is_some();
    let _ = dup.kill();
    assert!(ended, "a second copy kept running");
    assert!(door_line(&sock, "LIST").await.lines().any(|l| l == "restart.test 1"), "two copies listed");

    // a copy supervised outside the door (an orphan, like a systemd unit's process): it wins, the door stops its own
    let out = std::process::Command::new("sh")
        .args(["-c", &format!("'{}' --exact restart_cell --ignored --nocapture >/dev/null 2>&1 & echo $!", std::env::current_exe().unwrap().display())])
        .output()
        .unwrap();
    let outside: u32 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
    let p1b = pid_within(door, p1, 10_000).await.expect("the supervised copy never took over");
    assert_eq!(p1b, outside);
    // gone or a zombie (the door's child, reaped later)
    let ended = |p: u32| std::fs::read_to_string(format!("/proc/{p}/stat")).map(|st| st.rsplit_once(')').map_or(true, |r| r.1.trim_start().starts_with('Z'))).unwrap_or(true);
    let t = std::time::Instant::now();
    while !ended(p1) && t.elapsed().as_secs() < 10 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(ended(p1), "the door's copy kept running");
    assert!(door_line(&sock, "LIST").await.lines().any(|l| l == "restart.test 1"), "two copies after the takeover");
    let p1 = p1b;

    // it exits by itself (code 3): the door starts a new process after 200 ms
    let c = Client::<Cell>::connect(door, vec![]).await.unwrap();
    c.call::<Die>(&()).await.unwrap();
    let p2 = pid_within(door, p1, 10_000).await.expect("not restarted after it ended by itself");
    assert_ne!(p1, p2);

    // a planned restart (deploy): the old process is stopped first, a new one serves, one copy listed
    let r = door_line(&sock, "RESTART restart.test").await;
    assert!(r.contains("restarted restart.test (1 old"), "{r}");
    let p3 = pid_within(door, p2, 10_000).await.expect("not back after RESTART");
    assert_ne!(p2, p3);
    assert!(door_line(&sock, "LIST").await.lines().any(|l| l == "restart.test 1"), "two copies after RESTART");
    let p2 = p3;
    let _ = p2;

    // stopped through the door by its owner (one op for every cell an owner owns): another owner's stop leaves it, its
    // own owner's stop takes it down and it stays down (no call is made, a call would start it on demand)
    let r = door_line(&sock, "STOP-OWNER other-owner shutting down").await;
    assert!(r.contains("stopped 0 cell(s) of other-owner"), "{r}");
    let r = door_line(&sock, "STOP-OWNER foreman/restart-owner off for 3 days").await;
    assert!(r.contains("stopped 1 cell(s) of restart-owner: restart.test (1)"), "{r}");
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    assert!(!listed(&sock).await, "a stopped cell came back");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_cell_started_by_systemd_is_never_started_by_the_door() {
    let d = std::env::temp_dir().join(format!("ce-wire-by-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let m = d.join("cell.toml");
    std::fs::write(&m, "[cell]\napi = \"x\"\n[launch]\nby = \"systemd\"  # unit twin-registry\nrestart_backoff_ms = [100, 1000]\n").unwrap();
    assert_eq!(ce_wire::launched_by(&m).as_deref(), Some("systemd"));
    std::fs::write(&m, "[cell]\nby = \"systemd\"\n[launch]\nby = \"door\"\n").unwrap();
    assert_eq!(ce_wire::launched_by(&m), None);
    let _ = std::fs::remove_dir_all(&d);
}
