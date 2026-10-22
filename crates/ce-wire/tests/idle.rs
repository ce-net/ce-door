//! Scale to zero (door/idle.rs): the door stops a function cell it started once nobody has used it for
//! `CE_DOOR_IDLE_S`, and the next Hello starts it again, also a Hello that may not spawn. A cell with an open
//! connection, one that works in the background (CPU), one marked `keep = true` and one in the autostart file stay up.
//! The cells are this test binary run as `<name>_cell` (ignored tests).
use ce_wire::{Caller, Client, Server};
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

macro_rules! cell {
    ($m:ident, $api:literal, $run:ident, $work:expr) => {
        mod $m {
            ce_wire::api! {
                api Cell = $api, version 1;
                types { pub struct P { pub pid: u32 } }
                ops { 1 => Pid(()) -> P, needs "i.x"; }
            }
        }
        #[tokio::test]
        #[ignore = "a cell process the idle test spawns"]
        async fn $run() {
            let work: fn() = $work;
            std::thread::spawn(work);
            let s = Server::<$m::Cell>::new(|_| Ok(Caller { name: "t".into(), rights: vec!["i.x".into()] }))
                .on::<$m::Pid, _, _>(|_, _| async move { Ok($m::P { pid: std::process::id() }) });
            let _ = s.serve_door().await;
        }
    };
}

cell!(quiet, "idle.test", idle_cell, || {});
cell!(kept, "idle.keep", keep_cell, || {});
cell!(auto, "idle.auto", auto_cell, || {});
// background work with no caller: 30 ms of CPU every 200 ms
cell!(busy, "idle.busy", busy_cell, || loop {
    let t = Instant::now();
    while t.elapsed() < Duration::from_millis(30) {
        std::hint::black_box(0u64.wrapping_add(1));
    }
    std::thread::sleep(Duration::from_millis(200));
});

/// The door tests set process-wide env (socket, port, idle time) that the cells they spawn inherit: one at a time.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

async fn door_line(sock: &Path, line: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::UnixStream::connect(sock).await.unwrap();
    s.write_all(format!("{line}\n").as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    out
}

async fn listed(sock: &Path, api: &str) -> bool {
    door_line(sock, "LIST").await.lines().any(|l| l.starts_with(&format!("{api} ")))
}

/// Wait up to `ms` for `f` to hold.
async fn within(ms: u64, mut f: impl AsyncFnMut() -> bool) -> bool {
    let t = Instant::now();
    while t.elapsed().as_millis() < ms as u128 {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// One call to idle.test through the door: (pid, ms from dial to answer). `spawn`: whether the Hello may start it.
async fn pid_of(door: SocketAddr, spawn: bool) -> Result<(u32, u128), ce_wire::WireError> {
    let t = Instant::now();
    let c = Client::<quiet::Cell>::connect_opts(door, vec![], spawn, ce_wire::SPAWN_WAIT + ce_wire::DEADLINE).await?;
    let quiet::P { pid } = c.call::<quiet::Pid>(&()).await?;
    Ok((pid, t.elapsed().as_millis()))
}

fn gone(p: u32) -> bool {
    // gone, or a zombie the door reaps
    std::fs::read_to_string(format!("/proc/{p}/stat")).map(|st| st.rsplit_once(')').is_none_or(|r| r.1.trim_start().starts_with('Z'))).unwrap_or(true)
}

#[test]
fn which_cells_may_stop_when_idle() {
    use ce_wire::idle_stoppable as s;
    assert!(s("[cell]\napi = \"a.b\"\nkind = \"function\"\n").is_ok());
    assert_eq!(s("[cell]\napi = \"a.b\"\nkind = \"function\"\nkeep = true  # polls a feed\n"), Err("keep = true".into()));
    assert_eq!(s("[cell]\nkind = \"function\"\nidle_stop = false\n"), Err("idle_stop = false".into()));
    assert!(s("[cell]\nkind = \"ui-state\"\nidle_stop = true\n").is_ok());
    assert!(s("[cell]\nkind = \"ui-state\"\n").unwrap_err().contains("kind ui-state"));
    assert!(s("[cell]\napi = \"a.b\"\n").is_err(), "no kind: kept");
    // `kind` of another table is not the cell's
    assert!(s("[cell]\napi = \"a.b\"\n[launch]\nkind = \"function\"\n").is_err());
    assert_eq!(ce_wire::IDLE_DEFAULT_S, 900);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_idle_cell_stops_and_the_next_call_starts_it() {
    let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let root = std::env::temp_dir().join(format!("ce-idle-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (apps, home) = (root.join("apps"), root.join("home"));
    std::fs::create_dir_all(&home).unwrap();
    let exe = std::env::current_exe().unwrap().display().to_string();
    for (dir, api, run, extra) in [
        ("quiet", "idle.test", "idle_cell", "owner = \"foreman/idle-owner\"\n"),
        ("kept", "idle.keep", "keep_cell", "keep = true  # works on a timer\n"),
        ("auto", "idle.auto", "auto_cell", ""),
        ("busy", "idle.busy", "busy_cell", ""),
    ] {
        std::fs::create_dir_all(apps.join(dir)).unwrap();
        std::fs::write(
            apps.join(dir).join("cell.toml"),
            format!("[cell]\napi = \"{api}\"\nkind = \"function\"\n{extra}spawn = [\"{exe}\", \"--exact\", \"{run}\", \"--ignored\", \"--nocapture\"]\n"),
        )
        .unwrap();
    }
    std::fs::write(root.join("autostart"), "idle.auto   # always on here\n").unwrap();
    let sock = root.join("door.sock");
    let port = { std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() };
    std::env::set_var("CE_DOOR_IDLE_S", "2");
    std::env::set_var("CE_DOOR_AUTOSTART", root.join("autostart"));
    std::env::set_var("CE_DOOR_PORT", port.to_string());
    std::env::set_var("CE_DOOR_SOCK", &sock);
    std::env::set_var("CE_WIRE_PEERS", "");
    std::env::set_var("CE_WIRE_APPS", &apps);
    std::env::set_var("CE_DOOR_ROOM", "none");
    std::env::set_var("HOME", &home);
    tokio::spawn(ce_wire::run_door(vec![([127, 0, 0, 1], port).into()], sock.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let door = SocketAddr::from(([127, 0, 0, 1], port));

    // first call starts it (a spawning Hello, the caller's last step)
    let (p1, cold1) = pid_of(door, true).await.expect("first call");
    eprintln!("idle test: cold start through a spawning Hello: {cold1} ms");
    for api in ["idle.keep", "idle.auto", "idle.busy"] {
        door_line(&sock, &format!("PLACE {api}")).await;
        assert!(within(10_000, async || listed(&sock, api).await).await, "{api} never registered");
    }

    // an open connection holds it: idle 2 s, held 4 s, still the same process
    let held = Client::<quiet::Cell>::connect(door, vec![]).await.unwrap();
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(held.call::<quiet::Pid>(&()).await.unwrap().pid, p1, "stopped under an open connection");
    drop(held);

    // let go: stopped within idle (2 s) + one sweep (1 s) + margin, and the process ends
    assert!(within(8_000, async || !listed(&sock, "idle.test").await).await, "idle.test still listed: {}", door_line(&sock, "IDLE").await);
    assert!(within(8_000, async || gone(p1)).await, "pid {p1} still runs");
    let report = door_line(&sock, "IDLE").await;
    eprintln!("idle test: IDLE\n{report}");
    assert!(report.lines().any(|l| l.starts_with("idle.keep ") && l.contains("keep: keep = true")), "{report}");
    assert!(report.lines().any(|l| l.starts_with("idle.auto ") && l.contains("autostart")), "{report}");
    assert!(report.lines().any(|l| l.starts_with("idle.busy ") && l.contains("busy: used CPU")), "{report}");
    assert!(report.lines().last().unwrap().contains("stopped: idle.test"), "{report}");
    for api in ["idle.keep", "idle.auto", "idle.busy"] {
        assert!(listed(&sock, api).await, "{api} was stopped");
    }

    // a Hello that may not spawn (a mesh peer's or the finder's dial) starts it again, transparently
    let (p2, cold2) = pid_of(door, false).await.expect("call after the idle stop");
    eprintln!("idle test: cold start after an idle stop (Hello without spawn): {cold2} ms");
    assert_ne!(p1, p2);
    assert!(cold2 < 5_000, "cold start {cold2} ms");
    // warm: no start
    let (p3, warm) = pid_of(door, false).await.unwrap();
    eprintln!("idle test: warm call: {warm} ms");
    assert_eq!(p2, p3);

    // idle again, then stopped on purpose by its owner: it stays down, a Hello without spawn no longer wakes it
    assert!(within(8_000, async || !listed(&sock, "idle.test").await).await, "not stopped the second time");
    let r = door_line(&sock, "STOP-OWNER idle-owner done for today").await;
    assert!(r.contains("stopped 1 cell(s) of idle-owner: idle.test (idle)"), "{r}");
    assert!(pid_of(door, false).await.is_err(), "a stopped cell was woken");
    assert!(!door_line(&sock, "IDLE").await.lines().last().unwrap().contains("idle.test"));

    for api in ["idle.keep", "idle.auto", "idle.busy"] {
        door_line(&sock, &format!("STOP {api}")).await;
    }
    std::env::remove_var("CE_DOOR_IDLE_S");
    let _ = std::fs::remove_dir_all(&root);
}

/// Cold start of real cells, spawn to registration, on a door of its own (temp socket and port; the machine's door and
/// its cells are not touched): `CE_IDLE_BENCH="<api>=<binary> ..." cargo test --test idle -- --ignored cold_start_of_real_cells`.
/// Each binary runs as `<binary> serve` in an empty folder, five times, stopped each time by the idle sweep (1 s). stopped each time by the idle sweep (1 s).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measures binaries named in CE_IDLE_BENCH"]
async fn cold_start_of_real_cells() {
    let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Ok(bench) = std::env::var("CE_IDLE_BENCH") else { return };
    let root = std::env::temp_dir().join(format!("ce-idle-bench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let apps = root.join("apps");
    let pairs: Vec<(String, String)> = bench.split_whitespace().filter_map(|p| p.split_once('=')).map(|(a, b)| (a.into(), b.into())).collect();
    for (api, bin) in &pairs {
        let d = apps.join(api);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("cell.toml"), format!("[cell]\napi = \"{api}\"\nkind = \"function\"\nspawn = [\"{bin}\", \"serve\"]\n")).unwrap();
    }
    let sock = root.join("door.sock");
    let port = { std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() };
    std::env::set_var("CE_DOOR_IDLE_S", "1");
    std::env::set_var("CE_DOOR_PORT", port.to_string());
    std::env::set_var("CE_DOOR_SOCK", &sock);
    std::env::set_var("CE_WIRE_PEERS", "");
    std::env::set_var("CE_WIRE_APPS", &apps);
    std::env::set_var("CE_DOOR_ROOM", "none");
    tokio::spawn(ce_wire::run_door(vec![([127, 0, 0, 1], port).into()], sock.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;
    for (api, _) in &pairs {
        let mut ms = Vec::new();
        for _ in 0..5 {
            let t = Instant::now();
            door_line(&sock, &format!("PLACE {api}")).await;
            if !within(10_000, async || listed(&sock, api).await).await {
                eprintln!("bench {api}: did not register in 10 s");
                break;
            }
            ms.push(t.elapsed().as_millis());
            // the idle stop (1 s) takes it down, the way a call after one finds it
            if !within(10_000, async || !listed(&sock, api).await).await {
                let why = door_line(&sock, "IDLE").await;
                eprintln!("bench {api}: not idle-stopped in 10 s: {}", why.lines().find(|l| l.starts_with(api.as_str())).unwrap_or(""));
                door_line(&sock, &format!("STOP {api}")).await;
                break;
            }
        }
        ms.sort();
        eprintln!("bench {api}: spawn to registered {ms:?} ms");
    }
    let _ = std::fs::remove_dir_all(&root);
}

mod saver {
    ce_wire::api! {
        api Cell = "idle.save", version 1;
        types { pub struct P { pub pid: u32 } }
        ops { 1 => Pid(()) -> P, needs "i.x"; }
    }
}

/// A cell with a dying routine: writes `pid <pid> <reason>` to `$APO_FILE` and says so. `$APO_SLOW_MS`: it takes that
/// long, with 300 ms granted.
#[tokio::test]
#[ignore = "a cell process the apoptosis test spawns"]
async fn save_cell() {
    let file = std::env::var("APO_FILE").unwrap();
    let slow: u64 = std::env::var("APO_SLOW_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let routine = move |r: ce_wire::ApoptosisReq| {
        let file = file.clone();
        async move {
            tokio::time::sleep(Duration::from_millis(slow)).await;
            let body = format!("pid {} {}\n", std::process::id(), r.reason);
            std::fs::write(&file, &body).map_err(|e| e.to_string())?;
            Ok(ce_wire::Saved { bytes: body.len() as u64, at: file })
        }
    };
    let s = Server::<saver::Cell>::new(|_| Ok(Caller { name: "t".into(), rights: vec!["i.x".into()] }))
        .on::<saver::Pid, _, _>(|_, _| async move { Ok(saver::P { pid: std::process::id() }) });
    let s = if slow > 0 { s.on_apoptosis_within(300, routine) } else { s.on_apoptosis(routine) };
    let _ = s.serve_door().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cell_saves_before_it_dies() {
    let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let root = std::env::temp_dir().join(format!("ce-apoptosis-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let apps = root.join("apps");
    std::fs::create_dir_all(apps.join("save")).unwrap();
    let exe = std::env::current_exe().unwrap().display().to_string();
    std::fs::write(apps.join("save/cell.toml"), format!("[cell]\napi = \"idle.save\"\nkind = \"function\"\nspawn = [\"{exe}\", \"--exact\", \"save_cell\", \"--ignored\", \"--nocapture\"]\n")).unwrap();
    let saved = root.join("saved.txt");
    let sock = root.join("door.sock");
    let port = { std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() };
    std::env::set_var("CE_DOOR_IDLE_S", "0");
    std::env::set_var("CE_DOOR_PORT", port.to_string());
    std::env::set_var("CE_DOOR_SOCK", &sock);
    std::env::set_var("CE_WIRE_PEERS", "");
    std::env::set_var("CE_WIRE_APPS", &apps);
    std::env::set_var("CE_DOOR_ROOM", "none");
    std::env::set_var("APO_FILE", &saved);
    let door = SocketAddr::from(([127, 0, 0, 1], port));
    let (srv, door_sock) = (door, sock.clone());
    tokio::spawn(ce_wire::run_door(vec![srv], door_sock));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let pid = || async {
        let c = Client::<saver::Cell>::connect_opts(door, vec![], true, ce_wire::SPAWN_WAIT + ce_wire::DEADLINE).await.unwrap();
        c.call::<saver::Pid>(&()).await.unwrap().pid
    };

    // stopped through the door: it is asked first, saves, and the answer says what and where
    let p1 = pid().await;
    let t = Instant::now();
    let r = door_line(&sock, "STOP idle.save").await;
    eprintln!("apoptosis test: STOP answered in {} ms: {}", t.elapsed().as_millis(), r.trim());
    assert!(r.contains(&format!("pid {p1} saved")) && r.contains(&saved.display().to_string()), "{r}");
    assert_eq!(std::fs::read_to_string(&saved).unwrap(), format!("pid {p1} stop\n"));
    assert!(within(8_000, async || gone(p1)).await, "pid {p1} still runs");

    // a routine slower than its time: the door does not wait for it, the stop goes on
    std::fs::remove_file(&saved).unwrap();
    std::env::set_var("APO_SLOW_MS", "1500");
    let p2 = pid().await;
    let t = Instant::now();
    let r = door_line(&sock, "STOP idle.save").await;
    assert!(r.contains(&format!("pid {p2} did not save: not done in 300 ms")), "{r}");
    assert!(t.elapsed() < Duration::from_millis(1200), "waited {} ms", t.elapsed().as_millis());
    std::env::remove_var("APO_SLOW_MS");
    assert!(within(8_000, async || gone(p2)).await);

    // SIGTERM (systemd, kill) runs the same routine, then the process exits 0
    let p3 = pid().await;
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(p3 as i32), nix::sys::signal::Signal::SIGTERM).unwrap();
    assert!(within(5_000, async || std::fs::read_to_string(&saved).is_ok_and(|s| s == format!("pid {p3} SIGTERM\n"))).await, "SIGTERM did not save");
    assert!(within(8_000, async || gone(p3)).await);

    // a cell built before apoptosis (no apo= on REGISTER) is stopped without being asked, at once
    use std::io::{Read, Write};
    let mut old = std::os::unix::net::UnixStream::connect(&sock).unwrap();
    writeln!(old, "REGISTER idle.old 0000000000000001 0 wire=3").unwrap();
    assert!(within(5_000, async || listed(&sock, "idle.old").await).await);
    let t = Instant::now();
    let r = door_line(&sock, "STOP idle.old").await;
    assert_eq!(r.trim(), "stopped 1 process(es) of idle.old");
    assert!(t.elapsed() < Duration::from_millis(500));
    let mut b = [0u8; 16];
    assert_eq!(old.read(&mut b).unwrap(), 0, "the old cell got bytes it does not know");
    let _ = std::fs::remove_dir_all(&root);
}

/// Cold start after an idle stop, first Hello to answer, p50/p95 over 20 rounds, with `n` cell.tomls in the apps
/// tree (868 on one host). `CE_WIRE_MANIFEST_CACHE=0` measures the walk on every start (before the cache):
/// `CE_IDLE_COLD_N=868 cargo test --test idle -- --ignored --exact cold_start_p50_p95 --nocapture`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "a measurement"]
async fn cold_start_p50_p95() {
    let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let n: usize = std::env::var("CE_IDLE_COLD_N").ok().and_then(|s| s.parse().ok()).unwrap_or(868);
    let root = std::env::temp_dir().join(format!("ce-idle-cold-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let apps = root.join("apps");
    for i in 0..n {
        let d = apps.join(format!("g{}", i % 30)).join(format!("other-{i}"));
        std::fs::create_dir_all(d.join("src")).unwrap();
        std::fs::write(d.join("cell.toml"), format!("[cell]\napi = \"other.c{i}\"\nkind = \"function\"\n")).unwrap();
    }
    // the cell itself sits last in walk order, like most of 868
    std::fs::create_dir_all(apps.join("zz/quiet")).unwrap();
    let exe = std::env::current_exe().unwrap().display().to_string();
    std::fs::write(apps.join("zz/quiet/cell.toml"), format!("[cell]\napi = \"idle.test\"\nkind = \"function\"\nspawn = [\"{exe}\", \"--exact\", \"idle_cell\", \"--ignored\"]\n")).unwrap();
    let sock = root.join("door.sock");
    let port = { std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() };
    std::env::set_var("CE_DOOR_IDLE_S", "1");
    std::env::set_var("CE_DOOR_PORT", port.to_string());
    std::env::set_var("CE_DOOR_SOCK", &sock);
    std::env::set_var("CE_WIRE_PEERS", "");
    std::env::set_var("CE_WIRE_APPS", &apps);
    std::env::set_var("CE_DOOR_ROOM", "none");
    tokio::spawn(ce_wire::run_door(vec![([127, 0, 0, 1], port).into()], sock.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let door = SocketAddr::from(([127, 0, 0, 1], port));
    let t = Instant::now();
    for _ in 0..50 {
        ce_wire::find_manifest("idle.test").unwrap();
    }
    let walk_us = t.elapsed().as_micros() / 50;
    pid_of(door, true).await.unwrap();
    let mut ms = Vec::new();
    for _ in 0..20 {
        assert!(within(10_000, async || !listed(&sock, "idle.test").await).await, "{}", door_line(&sock, "IDLE").await);
        let (_, t) = pid_of(door, false).await.unwrap();
        ms.push(t);
    }
    ms.sort();
    eprintln!(
        "cold start, {n} cell.tomls, cache {}: find_manifest {walk_us} us; first Hello to answer p50 {} ms p95 {} ms max {} ms ({ms:?})",
        std::env::var("CE_WIRE_MANIFEST_CACHE").unwrap_or_else(|_| "on".into()),
        ms[ms.len() / 2],
        ms[ms.len() * 95 / 100],
        ms[ms.len() - 1]
    );
    let _ = std::fs::remove_dir_all(&root);
}
