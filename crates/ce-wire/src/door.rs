//! One ce-wire door per machine (D12a): as many cells as wanted per machine.
//!
//! The door listens on one fixed TCP port (`DOOR_PORT`) on 127.0.0.1 and the node's net.mesh address. A client sends
//! its Hello there as to any cell. The door reads the Hello, picks a registered process of that cell (starting one if
//! none runs), and hands the TCP socket itself to that process with SCM_RIGHTS, together with the Hello bytes. From
//! then on client and cell talk directly; the door is out of the path. Cells register over a Unix socket that only
//! this user can open (`door_sock()`, mode 0600); the registration lives as long as that Unix connection.
//!
//! Control protocol on the Unix socket:
//! - cell -> door, once: `REGISTER <api>[#<instance>] <schema hex> <pid>\n` (instances: `ce_wire::instance_key`;
//!   a Hello for `<api>#<instance>` reaches that instance only, a Hello for the bare `<api>` any process of the api)
//! - door -> cell, per connection: `u32 LE len | Hello frame (len bytes)` with the TCP fd attached as SCM_RIGHTS.
use crate::net::Inner;
use crate::proto::{frame, Hello, Refusal};
use crate::{Api, Kind, Server, WireError};
use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};
use std::collections::{BTreeMap, HashMap};
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Interest};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::Notify;

/// `$CE_DOOR_SOCK` or `~/.ce/wire-door.sock`.
pub fn door_sock() -> PathBuf {
    std::env::var("CE_DOOR_SOCK").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/".into())).join(".ce/wire-door.sock")
    })
}

mod drift;
mod idle;
pub use idle::{idle_after, IDLE_DEFAULT_S};

struct Cell {
    id: u64,
    pid: u32,
    /// The name it registered under (`<api>` or `<api>#<instance>`).
    name: String,
    schema: String,
    /// The git rev the process was built from (`rev=` on REGISTER, from `$CE_CELL_REV`), when it says.
    rev: Option<String>,
    /// Older schema hashes it also answers (`accepts=` on REGISTER: `ACCEPTS` plus its typed adapters).
    accepts: Vec<u64>,
    /// The wire revision it serves (`wire=` on REGISTER; 2 when it does not say). A wire-3 cell checks a wire-3
    /// caller op by op, so the door hands it a caller whose whole schema differs.
    wire: u32,
    /// Its per-op hashes (`ops=<id>:<hex>,...` on REGISTER): a wire-3 caller is handed to it op by op only when at
    /// least one of the caller's ops hashes the same, the cell's own admission rule ([`crate::per_op_admit`]).
    ops: Vec<(u32, u64)>,
    /// The time its dying routine may take (`apo=<ms>` on REGISTER); None: a cell built before apoptosis, stopped
    /// without asking (src/apoptosis.rs).
    apo: Option<u32>,
    /// Its answer to the apoptosis request, filled by the registration's read loop.
    saved: Arc<Saved>,
    ctl: Arc<UnixStream>,
}

/// STOP's way out: each cell runs its dying routine ([`apoptosis`]), then its registration is closed, so its
/// `serve_door` returns and the process ends. What each cell saved, one line per cell that has a routine.
async fn close_after_apoptosis(gone: Vec<Cell>, why: String) -> Vec<String> {
    tokio::task::spawn_blocking(move || {
        let said = apoptosis(&gone, &why);
        for c in &gone {
            let _ = nix::sys::socket::shutdown(c.ctl.as_raw_fd(), nix::sys::socket::Shutdown::Both);
        }
        said
    })
    .await
    .unwrap_or_default()
}

/// How long past a cell's deadline the door still waits for its answer to arrive.
const APOPTOSIS_SLACK_MS: u64 = 200;

/// One cell's answer to an apoptosis request, and the signal that it came.
type Saved = (Mutex<Option<Result<crate::Saved, String>>>, std::sync::Condvar);

/// Ask every cell in `gone` that has a dying routine to run it, all at once, and wait for each answer up to that
/// cell's time. Blocking (stop paths run it on a blocking thread). Each outcome is a door event (`ce-door watch`):
/// `apoptosis <api> saved <bytes> B to <where> in <ms> ms`, or the error / missing answer. The answers, one per cell.
fn apoptosis(gone: &[Cell], why: &str) -> Vec<String> {
    let t0 = std::time::Instant::now();
    let asked: Vec<(&Cell, u32)> = gone
        .iter()
        .filter_map(|c| {
            let ms = c.apo?;
            let f = crate::apo_frame(crate::APO_MARK, &crate::ApoptosisReq { reason: why.to_string(), deadline_ms: ms });
            *c.saved.0.lock().unwrap() = None;
            let mut off = 0;
            let until = t0 + std::time::Duration::from_millis(ms as u64);
            while off < f.len() && std::time::Instant::now() < until {
                match c.ctl.try_write(&f[off..]) {
                    Ok(n) => off += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(std::time::Duration::from_millis(1)),
                    Err(_) => return None,
                }
            }
            (off == f.len()).then_some((c, ms))
        })
        .collect();
    let mut out = Vec::new();
    for (c, ms) in asked {
        // the cell's own timeout ends its routine at `ms`; the slack lets that "not done" answer arrive
        let until = t0 + std::time::Duration::from_millis(ms as u64 + APOPTOSIS_SLACK_MS);
        let mut g = c.saved.0.lock().unwrap();
        while g.is_none() {
            let left = until.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                break;
            }
            g = c.saved.1.wait_timeout(g, left).unwrap().0;
        }
        let line = match g.take() {
            Some(Ok(s)) if s.bytes == 0 && s.at.is_empty() => format!("pid {} nothing to save", c.pid),
            Some(Ok(s)) => format!("pid {} saved {} B to {} in {} ms", c.pid, s.bytes, s.at, t0.elapsed().as_millis()),
            Some(Err(e)) => format!("pid {} did not save: {e}", c.pid),
            None => format!("pid {} no answer in {ms} ms", c.pid),
        };
        crate::emit("apoptosis", &c.name, &format!("{why}: {line}"));
        out.push(line);
    }
    out
}

/// Decides whether a Hello may make this door start a cell that is not running (`run_door_gated`).
pub type SpawnGate = Arc<dyn Fn(&Hello) -> Result<(), String> + Send + Sync>;

#[derive(Default)]
struct Registry {
    /// Keyed by the registered name: the api, or `<api>#<instance>`. Sorted, so a bare api finds its instances by range.
    cells: Mutex<BTreeMap<String, Vec<Cell>>>,
    next: std::sync::atomic::AtomicU64,
    changed: Notify,
    spawn_gate: Option<SpawnGate>,
    /// Restarts in a row per api since it last stayed up `STEADY` (the backoff exponent).
    crashes: Mutex<HashMap<String, u32>>,
    /// Last use per registered name and the names stopped for idleness (`door/idle.rs`). Lock order: `cells` first.
    idle: Mutex<idle::Idle>,
    /// Stop a cell this door started after this long unused (`$CE_DOOR_IDLE_S`); zero = never.
    idle_after: std::time::Duration,
}

/// The registrations a Hello for `name` may reach: an instance name (`obs.source#wx.metar`) only its own; a bare api
/// its own and every `<api>#<instance>`. Each with the key it is registered under.
fn reach<'a>(m: &'a BTreeMap<String, Vec<Cell>>, name: &str) -> Vec<(&'a str, &'a Cell)> {
    let mut v: Vec<(&str, &Cell)> = m.get_key_value(name).map(|(k, c)| c.iter().map(|x| (k.as_str(), x)).collect()).unwrap_or_default();
    if crate::instance_of(name).is_none() {
        let from = format!("{name}{}", crate::INSTANCE_SEP);
        for (k, c) in m.range(from.clone()..).take_while(|(k, _)| k.starts_with(&from)) {
            v.extend(c.iter().map(|x| (k.as_str(), x)));
        }
    }
    v
}

/// True when a Hello for `name` has a process to go to ([`reach`] is not empty): what `ensure` asks before a spawn.
fn running_in(m: &BTreeMap<String, Vec<Cell>>, name: &str) -> bool {
    !reach(m, name).is_empty()
}

/// A cell that stayed registered this long counts as healthy: its next crash starts the backoff from the first value.
const STEADY: std::time::Duration = std::time::Duration::from_secs(60);

/// Run a door that starts a cell for any Hello that asks (tests, single-user boxes). The `ce-door` binary uses
/// [`run_door_gated`].
pub async fn run_door(binds: Vec<std::net::SocketAddr>, sock: PathBuf) -> std::io::Result<()> {
    run_door_gated(binds, sock, None).await
}

/// Run a door: TCP on every `binds` address, registrations and control on `sock`. A Hello for a cell that is not
/// running starts it (and its `needs`) only if `spawn_gate` accepts the Hello. Never returns unless binding fails.
///
/// Control lines on `sock` (this user only), one per connection, answered with one line:
/// - `REGISTER <api> <schema hex> <pid> [rev=<git rev>] [accepts=<hex>,...] [wire=<n>] [ops=<id>:<hex>,...]`: a cell process (see `serve_door`); the rev is `$CE_CELL_REV`;
/// - `PLACE <api>`: start the cell here if it does not run (the same path a spawning Hello takes, ungated: local user);
/// - `STOP <api>`: close every registration of the cell here; its `serve_door` returns and the process ends;
/// - `LIST`: the cells registered here, `<api> <processes>` per line;
/// - `LIST schema`: the same with the schema hashes, `<api> <processes> <schema hex>[,<schema hex>...]` per line
///   (distinct hashes of its processes, sorted). A door older than this answers plain `LIST`, so readers accept 2 fields;
/// - `BUILD <api> <sha> job=<id>`: host-room admits a queued schema-drift build (`door/drift.rs`);
/// - `WATCH`: the door's events (`ce_wire::emit`), kept ones first, then live, one line each;
/// - `IDLE`: per registered cell its idle seconds and whether it stops when idle (`door/idle.rs`), then the stopped ones.
///
/// A cell this door started is stopped after `$CE_DOOR_IDLE_S` (default 900 s, 0 = off) unused, and started again by
/// the next Hello for it (`door/idle.rs` lists what counts as use and what is never stopped).
pub async fn run_door_gated(binds: Vec<std::net::SocketAddr>, sock: PathBuf, spawn_gate: Option<SpawnGate>) -> std::io::Result<()> {
    run_door_inner(binds, sock, spawn_gate, None).await
}

/// [`run_door_gated`] on loopback plus every private overlay address of the underlay networks (`underlay::door_binds`:
/// ce-scale, tailscale, netbird, zerotier; never 0.0.0.0, never a public address). Every 60 s it looks again and binds
/// an address that appeared since (tailscale came up after boot, a new zerotier network joined).
pub async fn run_door_underlay(port: u16, sock: PathBuf, spawn_gate: Option<SpawnGate>) -> std::io::Result<()> {
    let binds = tokio::task::spawn_blocking(move || crate::underlay::door_binds(port)).await.unwrap_or_default();
    for (net, a) in &binds {
        eprintln!("ce-door: listening {a} ({})", net.map_or("loopback", |n| n.name()));
    }
    run_door_inner(binds.into_iter().map(|(_, a)| a).collect(), sock, spawn_gate, Some(port)).await
}

async fn run_door_inner(binds: Vec<std::net::SocketAddr>, sock: PathBuf, spawn_gate: Option<SpawnGate>, rescan: Option<u16>) -> std::io::Result<()> {
    let reg = Arc::new(Registry { spawn_gate, idle_after: idle::idle_after(), ..Default::default() });
    if let Some(d) = sock.parent() {
        std::fs::create_dir_all(d)?;
    }
    reg.idle.lock().unwrap().keep_in(sock.with_file_name("idle-stopped"));
    // A second door (a bare `ce-door` typed by hand) used to unlink the live socket, then die on the port, leaving the
    // machine with no registration socket (2026-10-13 21:09). Only a dead socket file is replaced.
    if std::os::unix::net::UnixStream::connect(&sock).is_ok() {
        return Err(std::io::Error::new(std::io::ErrorKind::AddrInUse, format!("a door already serves {}", sock.display())));
    }
    let _ = std::fs::remove_file(&sock);
    let ul = UnixListener::bind(&sock)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
    }
    let r2 = reg.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = ul.accept().await {
            tokio::spawn(register(r2.clone(), s));
        }
    });
    tokio::spawn(idle::sweep_loop(reg.clone()));
    let r3 = reg.clone();
    tokio::spawn(async move {
        let mut t = tokio::time::interval(std::time::Duration::from_secs(60));
        let mut n = 0u64;
        loop {
            t.tick().await;
            let apis: Vec<String> = r3.cells.lock().unwrap().keys().cloned().collect();
            let again = n % 5 == 0;
            n += 1;
            tokio::task::spawn_blocking(move || {
                refresh_peers();
                if again {
                    apis.iter().for_each(|a| advertise(a));
                }
            });
        }
    });
    // The first address (loopback) must bind: failing there means another door owns the port. A VPN or mesh address
    // may not exist yet (tailscale down, mesh not up at boot): retry it every 10 s instead of exiting, so the door and
    // its cells (net.heal among them) stay up while the network heals.
    let mut set = tokio::task::JoinSet::new();
    let known: std::collections::HashSet<std::net::SocketAddr> = binds.iter().copied().collect();
    if let Some(port) = rescan {
        let reg = reg.clone();
        set.spawn(async move {
            let mut known = known;
            let mut t = tokio::time::interval(std::time::Duration::from_secs(60));
            t.tick().await;
            loop {
                t.tick().await;
                let now = tokio::task::spawn_blocking(move || crate::underlay::door_binds(port)).await.unwrap_or_default();
                for (net, b) in now {
                    if known.contains(&b) {
                        continue;
                    }
                    // not added to `known` on failure: the next scan tries again
                    if let Ok(l) = TcpListener::bind(b).await {
                        eprintln!("ce-door: {b}: bound ({})", net.map_or("loopback", |n| n.name()));
                        known.insert(b);
                        tokio::spawn(accept_loop(reg.clone(), l));
                    }
                }
            }
        });
    }
    for (i, b) in binds.into_iter().enumerate() {
        let l = match TcpListener::bind(b).await {
            Ok(l) => Some(l),
            Err(e) if i == 0 => return Err(e),
            Err(e) => {
                eprintln!("ce-door: {b}: {e}; retrying every 10 s");
                None
            }
        };
        let reg = reg.clone();
        set.spawn(async move {
            let l = match l {
                Some(l) => l,
                None => loop {
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    if let Ok(l) = TcpListener::bind(b).await {
                        eprintln!("ce-door: {b}: bound");
                        break l;
                    }
                },
            };
            accept_loop(reg, l).await
        });
    }
    while set.join_next().await.is_some() {}
    Ok(())
}

async fn accept_loop(reg: Arc<Registry>, l: TcpListener) {
    loop {
        let Ok((s, _)) = l.accept().await else { continue };
        let _ = s.set_nodelay(true);
        tokio::spawn(route(reg.clone(), s));
    }
}

async fn register(reg: Arc<Registry>, s: UnixStream) {
    let s = Arc::new(s);
    let mut line = String::new();
    {
        let mut r = BufReader::new(ReadHalfRef(&s));
        if r.read_line(&mut line).await.is_err() {
            return;
        }
    }
    let mut it = line.split_whitespace();
    match (it.next(), it.next()) {
        (Some("PLACE"), Some(api)) => {
            let r2 = reg.clone();
            let running = move |a: &str| running_in(&r2.cells.lock().unwrap(), a);
            let api = api.to_string();
            let r = tokio::task::spawn_blocking(move || crate::ensure(&api, &running)).await.unwrap_or_else(|e| Err(e.to_string()));
            return answer(&s, r.unwrap_or_else(|e| format!("error {e}"))).await;
        }
        (Some("STOP"), Some(api)) => {
            // a cell systemd supervises (`[launch] unit`): stop the unit first, or systemd starts it again at once
            let a2 = api.to_string();
            let unit = tokio::task::spawn_blocking(move || crate::name::unit_of(&a2).map(|u| crate::name::systemctl("stop", &u))).await.ok().flatten();
            if let Some(Err(e)) = unit {
                return answer(&s, format!("error {api}: {e}")).await;
            }
            let gone: Vec<Cell> = { reg.cells.lock().unwrap().remove(api).unwrap_or_default() };
            // stopped for idleness before: now stopped on purpose, so a Hello that may not spawn no longer wakes it
            reg.idle.lock().unwrap().forget(api);
            // the old spawn is over: without this a spawning Hello within SPAWN_WINDOW (30 s) "attaches" to it and
            // waits 10 s for a cell that never registers
            crate::name::spawned(api);
            crate::emit("stop", api, &format!("{} process(es)", gone.len()));
            reg.changed.notify_waiters();
            let n = gone.len();
            let said = close_after_apoptosis(gone, "stop".into()).await;
            let said = if said.is_empty() { String::new() } else { format!(" ({})", said.join("; ")) };
            return answer(&s, format!("stopped {n} process(es) of {api}{said}")).await;
        }
        // Every cell an owner owns (`[cell] owner` in its cell.toml), stopped like STOP: one op shuts an owner's cells down
        // over ce-net, not through a separate system. The rest of
        // the line is the reason, written to the event log.
        (Some("STOP-OWNER"), Some(owner)) => {
            let owner = crate::lane_name(owner).to_string();
            let why = it.collect::<Vec<_>>().join(" ");
            let mut names: Vec<String> = reg.cells.lock().unwrap().keys().cloned().collect();
            // the owner's cells the door stopped for idleness stay down too (no Hello wakes them)
            names.extend(reg.idle.lock().unwrap().stopped().cloned());
            names.sort();
            names.dedup();
            let l2 = owner.clone();
            let mine: Vec<String> = tokio::task::spawn_blocking(move || {
                names.into_iter().filter(|n| crate::owner_of(n).as_deref() == Some(l2.as_str())).collect()
            })
            .await
            .unwrap_or_default();
            let mut done = Vec::new();
            for api in &mine {
                let gone: Vec<Cell> = { reg.cells.lock().unwrap().remove(api).unwrap_or_default() };
                crate::name::spawned(api);
                if reg.idle.lock().unwrap().forget(api) && gone.is_empty() {
                    crate::emit("stop", api, &format!("idle-stopped, now stopped, owner {owner}: {why}"));
                    done.push(format!("{api} (idle)"));
                    continue;
                }
                crate::emit("stop", api, &format!("{} process(es), owner {owner}: {why}", gone.len()));
                done.push(format!("{api} ({})", gone.len()));
                close_after_apoptosis(gone, format!("stop-owner {owner}: {why}")).await;
            }
            reg.changed.notify_waiters();
            return answer(&s, format!("stopped {} cell(s) of {owner}: {}", done.len(), done.join(", "))).await;
        }
        // A planned restart (deploy of a new binary): out of the registry first, like STOP, so it is never reported as
        // "ended by itself"; wait for the old processes to exit (stop_cells: 5 s, then SIGTERM), then start it again.
        // Killing the PID to pick up a binary made error.collect report every deploy as a crash.
        (Some("RESTART"), Some(api)) => {
            let gone: Vec<Cell> = { reg.cells.lock().unwrap().remove(api).unwrap_or_default() };
            let n = gone.len();
            crate::emit("stop", api, &format!("{n} process(es), restart"));
            reg.changed.notify_waiters();
            let r2 = reg.clone();
            let api = api.to_string();
            let r = tokio::task::spawn_blocking(move || {
                // a cell systemd supervises (`[launch] unit`): systemd stops and starts it, in its own cgroup
                if let Some(unit) = crate::name::unit_of(&api) {
                    return crate::name::systemctl("restart", &unit).map(|m| format!("restarted {api} ({n} old process(es)): {m}"));
                }
                stop_cells(gone, "restart");
                // the old spawn is over: without this a spawn within SPAWN_WINDOW (30 s) "attaches" and starts nothing
                crate::name::spawned(&api);
                let running = move |a: &str| running_in(&r2.cells.lock().unwrap(), a);
                crate::ensure(&api, &running).map(|m| format!("restarted {api} ({n} old process(es) stopped): {m}"))
            })
            .await
            .unwrap_or_else(|e| Err(e.to_string()));
            return answer(&s, r.unwrap_or_else(|e| format!("error {e}"))).await;
        }
        (Some("UPDATE"), Some(api)) => {
            let (r2, a2) = (reg.clone(), api.to_string());
            let swap = Box::new(move || {
                let gone: Vec<Cell> = { r2.cells.lock().unwrap().remove(&a2).unwrap_or_default() };
                crate::emit("stop", &a2, &format!("{} process(es), updated", gone.len()));
                r2.changed.notify_waiters();
                stop_cells(gone, "update");
            });
            let r = crate::update(api, swap);
            return answer(&s, r.unwrap_or_else(|e| format!("error {e}"))).await;
        }
        (Some("BUILD"), Some(api)) => {
            // host-room admits a queued drift update: `BUILD <api> <sha> job=<id>` (drift.rs)
            let (sha, job) = (it.next().unwrap_or_default(), it.next().and_then(|j| j.strip_prefix("job=")).unwrap_or_default());
            let (r2, a, sh, j) = (reg.clone(), api.to_string(), sha.to_string(), job.to_string());
            let r = tokio::task::spawn_blocking(move || drift::admitted(&r2, &a, &sh, &j)).await.unwrap_or_else(|e| e.to_string());
            return answer(&s, r).await;
        }
        (Some("WATCH"), _) => {
            // Every kept event, then each new one as it happens, one line each, until the watcher hangs up.
            let (old, rx) = crate::watch();
            let Ok(std_s) = Arc::try_unwrap(s).map_err(|_| ()).and_then(|u| u.into_std().map_err(|_| ())) else { return };
            let _ = std_s.set_nonblocking(false);
            let _ = tokio::task::spawn_blocking(move || {
                use std::io::Write;
                let mut w = std::io::BufWriter::new(&std_s);
                for l in old {
                    if writeln!(w, "{l}").is_err() {
                        return;
                    }
                }
                let _ = w.flush();
                while let Ok(l) = rx.recv() {
                    if writeln!(w, "{l}").and_then(|()| w.flush()).is_err() {
                        return;
                    }
                }
            })
            .await;
            return;
        }
        (Some("IDLE"), _) => {
            let r = idle::report(&reg);
            return answer(&s, r).await;
        }
        (Some("LIST"), Some("schema")) => {
            let mut v: Vec<String> = reg
                .cells
                .lock()
                .unwrap()
                .iter()
                .map(|(a, c)| {
                    let mut h: Vec<&str> = c.iter().map(|x| x.schema.as_str()).collect();
                    h.sort_unstable();
                    h.dedup();
                    format!("{a} {} {}", c.len(), h.join(","))
                })
                .collect();
            v.sort();
            return answer(&s, v.join("\n")).await;
        }
        (Some("LIST"), _) => {
            let mut v: Vec<String> = reg.cells.lock().unwrap().iter().map(|(a, c)| format!("{a} {}", c.len())).collect();
            v.sort();
            return answer(&s, v.join("\n")).await;
        }
        _ => {}
    }
    let mut it = line.split_whitespace();
    let (Some("REGISTER"), Some(api), Some(schema), Some(pid)) = (it.next(), it.next(), it.next(), it.next()) else { return };
    if !crate::valid_key(api) {
        eprintln!("ce-door: refused REGISTER {api}: not a valid name");
        let _ = nix::sys::socket::shutdown(s.as_raw_fd(), nix::sys::socket::Shutdown::Both);
        return;
    }
    let api = api.to_string();
    let schema = schema.to_string();
    let id = reg.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid: u32 = pid.parse().unwrap_or(0);
    let (mut rev, mut accepts, mut wire, mut ops, mut apo) = (None, Vec::new(), 2, Vec::new(), None);
    let saved: Arc<Saved> = Arc::default();
    for t in it {
        if let Some(w) = t.strip_prefix("wire=") {
            wire = w.parse().unwrap_or(2);
            continue;
        }
        if let Some(o) = t.strip_prefix("ops=") {
            ops = o.split(',').filter_map(|x| x.split_once(':')).filter_map(|(i, h)| Some((i.parse().ok()?, u64::from_str_radix(h, 16).ok()?))).collect();
            continue;
        }
        if let Some(r) = t.strip_prefix("rev=").filter(|r| !r.is_empty()) {
            rev = Some(r.to_string());
        } else if let Some(ms) = t.strip_prefix("apo=") {
            apo = ms.parse::<u32>().ok().map(|m| m.clamp(1, crate::APOPTOSIS_MAX_MS));
        } else if let Some(a) = t.strip_prefix("accepts=") {
            accepts = a.split(',').filter_map(|h| u64::from_str_radix(h, 16).ok()).collect();
        }
    }
    let t0 = std::time::Instant::now();
    // One live copy per api per door: update and restart take the old copy out of the registry before the new one
    // registers, so a second copy whose first is still alive is a race (seen: one cell twice at 291 MB, others
    // started by both the door and systemd). Closing its registration ends it.
    // A drift swap registers the new build beside the old one (other schema or rev) on purpose: only the same schema
    // and rev twice is a duplicate.
    let first = reg.cells.lock().unwrap().get(&api).and_then(|v| v.iter().find(|c| c.schema == schema && c.rev == rev && c.pid != 0 && c.pid != pid && alive(c.pid)).map(|c| c.pid));
    // Exception: the first copy is the door's own child and the new one is supervised outside the door (systemd,
    // launchd). The supervisor would restart its copy forever against the refusal (seen: several
    // cells refused every 10-30 s after a door restart's restore or an
    // on-demand spawn beat their units), so the supervised copy wins and the door stops its own.
    let me = std::process::id();
    let first = match first {
        Some(f) if descends_from(f, me) == Some(true) && descends_from(pid, me) == Some(false) => {
            let gone: Vec<Cell> = {
                let mut m = reg.cells.lock().unwrap();
                let v = m.entry(api.clone()).or_default();
                let (gone, keep): (Vec<Cell>, Vec<Cell>) = std::mem::take(v).into_iter().partition(|c| c.pid == f);
                *v = keep;
                gone
            };
            eprintln!("ce-door: {api}: pid {pid} is supervised outside the door; stopping the door's copy pid {f}");
            crate::emit("stop", &api, &format!("door copy pid {f}; supervised pid {pid} serves"));
            std::thread::spawn(move || stop_cells(gone, "a supervised copy serves"));
            None
        }
        f => f,
    };
    if let Some(first) = first {
        eprintln!("ce-door: refused a second {api} (pid {pid}): pid {first} already serves it");
        crate::emit("refused", &api, &format!("second copy pid {pid}; pid {first} serves"));
        let _ = nix::sys::socket::shutdown(s.as_raw_fd(), nix::sys::socket::Shutdown::Both);
        return;
    }
    {
        let mut m = reg.cells.lock().unwrap();
        m.entry(api.clone()).or_default().push(Cell { id, pid, name: api.clone(), schema, rev, accepts, wire, ops, apo, saved: saved.clone(), ctl: s.clone() });
        reg.idle.lock().unwrap().registered(&api);
    }
    reg.changed.notify_waiters();
    eprintln!("ce-door: + {api} pid {pid}");
    crate::emit("register", &api, &format!("pid {pid}"));
    let a = api.clone();
    tokio::task::spawn_blocking(move || advertise(&a));
    // The registration lives until the cell closes its end.
    // What the cell writes back: its answers to an apoptosis request (src/apoptosis.rs), for `stop_cells`.
    let mut b = [0u8; 512];
    let mut got = Vec::new();
    loop {
        if s.readable().await.is_err() {
            break;
        }
        match s.try_read(&mut b) {
            Ok(0) => break,
            Ok(n) => {
                got.extend_from_slice(&b[..n]);
                for f in crate::take_frames(&mut got) {
                    let r = postcard::from_bytes::<Result<crate::Saved, String>>(&f).unwrap_or_else(|e| Err(format!("unreadable answer: {e}")));
                    *saved.0.lock().unwrap() = Some(r);
                    saved.1.notify_all();
                }
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(_) => break,
        }
    }
    eprintln!("ce-door: - {api} pid {pid}");
    crate::emit("unregister", &api, &format!("pid {pid}"));
    // STOP and UPDATE take the cell out of the registry before they close it; still listed here = it ended by itself
    let (crashed, left) = {
        let mut m = reg.cells.lock().unwrap();
        let listed = m.get(&api).is_some_and(|v| v.iter().any(|c| c.id == id));
        if let Some(v) = m.get_mut(&api) {
            v.retain(|c| c.id != id);
            if v.is_empty() {
                m.remove(&api);
            }
        }
        (listed, m.get(&api).map_or(0, Vec::len))
    };
    if crashed && left == 0 {
        tokio::spawn(restart(reg, api, t0.elapsed()));
    }
}

/// Restart a cell that ended without `ce-door stop`/`update`, if its cell.toml asks for it (`restart_backoff_ms`)
/// and its binary is built (a restart never starts a build). Skipped when another process registered meanwhile.
async fn restart(reg: Arc<Registry>, api: String, lived: std::time::Duration) {
    let Some(m) = crate::find_manifest(&api) else { return };
    let Some((first, max)) = crate::restart_backoff(&m) else { return };
    if crate::name::launched_by(&m).is_some() {
        return;
    }
    let n = {
        let mut c = reg.crashes.lock().unwrap();
        let e = c.entry(api.clone()).or_insert(0);
        if lived >= STEADY {
            *e = 0;
        }
        *e += 1;
        *e - 1
    };
    let wait = crate::restart_wait(first, max, n);
    eprintln!("ce-door: {api} ended by itself after {} s; restart {} in {wait} ms", lived.as_secs(), n + 1);
    crate::emit("restart", &api, &format!("ended after {} s; try {} in {wait} ms", lived.as_secs(), n + 1));
    tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
    if running_in(&reg.cells.lock().unwrap(), &api) {
        return;
    }
    if crate::name::unbuilt(&m) {
        crate::emit("failed", &api, "restart skipped: binary not built");
        return;
    }
    let r2 = reg.clone();
    let running = move |a: &str| running_in(&r2.cells.lock().unwrap(), a);
    let a = api.clone();
    crate::name::spawned(&api);
    let r = tokio::task::spawn_blocking(move || crate::ensure(&a, &running)).await.unwrap_or_else(|e| Err(e.to_string()));
    eprintln!("ce-door: restart {api}: {}", r.unwrap_or_else(|e| format!("error {e}")));
}

/// Close each cell's registration (its `serve_door` returns and the process ends), wait up to 5 s for it to exit, then
/// TERM it: the new build may need what the old one holds (a port, a lock).
/// The process `pid` still exists (signal 0).
/// Whether `pid` is `anc` or a descendant of it (walks the parent chain in /proc); None where that cannot be read
/// (a gone pid, or not Linux), so callers keep their old behaviour.
fn descends_from(pid: u32, anc: u32) -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        let mut p = pid;
        for _ in 0..32 {
            if p == anc {
                return Some(true);
            }
            if p <= 1 {
                return Some(false);
            }
            let st = std::fs::read_to_string(format!("/proc/{p}/stat")).ok()?;
            // pid (comm) state ppid ...; comm may hold spaces or ')', so read after the last ')'
            p = st.rsplit_once(')')?.1.split_whitespace().nth(1)?.parse().ok()?;
        }
        Some(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, anc);
        None
    }
}

fn alive(pid: u32) -> bool {
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None).is_ok()
}

/// Close each cell's registration (its `serve_door` returns and the process ends), wait up to 5 s for it to exit, then
/// TERM it: the new build may need what the old one holds (a port, a lock). First [`apoptosis`] lets each cell save
/// what must survive; `why` is the reason it is told.
fn stop_cells(gone: Vec<Cell>, why: &str) {
    use nix::{sys::signal::{kill, Signal}, unistd::Pid};
    apoptosis(&gone, why);
    for c in &gone {
        let _ = nix::sys::socket::shutdown(c.ctl.as_raw_fd(), nix::sys::socket::Shutdown::Both);
    }
    for c in &gone {
        let p = Pid::from_raw(c.pid as i32);
        for _ in 0..50 {
            if c.pid == 0 || kill(p, None).is_err() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if c.pid != 0 && kill(p, None).is_ok() {
            let _ = kill(p, Signal::SIGTERM);
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
}

async fn answer(s: &UnixStream, text: String) {
    let b = format!("{text}\n");
    let mut off = 0;
    while off < b.len() && s.writable().await.is_ok() {
        match s.try_write(&b.as_bytes()[off..]) {
            Ok(n) => off += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(_) => return,
        }
    }
}

/// tokio's UnixStream read through a shared reference (it implements AsyncRead for &UnixStream only via split).
struct ReadHalfRef<'a>(&'a UnixStream);
impl tokio::io::AsyncRead for ReadHalfRef<'_> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        loop {
            match self.0.poll_read_ready(cx) {
                std::task::Poll::Ready(Ok(())) => {}
                other => return other,
            }
            match self.0.try_read(buf.initialize_unfilled()) {
                Ok(n) => {
                    buf.advance(n);
                    return std::task::Poll::Ready(Ok(()));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return std::task::Poll::Ready(Err(e)),
            }
        }
    }
}

async fn refuse(mut s: TcpStream, why: Refusal) {
    let _ = s.write_all(&frame(Kind::Hello, 0, 0, &postcard::to_stdvec(&why).unwrap())).await;
}

async fn route(reg: Arc<Registry>, mut s: TcpStream) {
    // The caller's address, so a drift log line names who is sending the stale (or schema-0) Hello.
    let peer = s.peer_addr().ok();
    // Read exactly the Hello frame, keeping its bytes to pass on.
    let mut hb = [0u8; crate::HEADER];
    let read = async {
        use tokio::io::AsyncReadExt;
        s.read_exact(&mut hb).await?;
        let h = crate::Header::decode(&hb).map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        if h.kind != Kind::Hello || h.len > 64 * 1024 {
            return Err(std::io::Error::other("first frame must be a Hello <= 64 KiB"));
        }
        let mut p = vec![0u8; h.len as usize];
        s.read_exact(&mut p).await?;
        Ok::<_, std::io::Error>(p)
    };
    let Ok(Ok(payload)) = tokio::time::timeout(crate::DEADLINE, read).await else { return };
    let (hello, ext, caller_ops) = match crate::split_hello_ops(&payload) {
        Ok(h) => h,
        Err(e) => return refuse(s, Refusal::Decode(e)).await,
    };
    if crate::instance_of(&hello.api) == Some("*") {
        // "which instances of this api run here": the names only (they are in the DHT as wire:<api>#<name> already)
        let base = crate::base_api(&hello.api);
        let mut v: Vec<String> = { reach(&reg.cells.lock().unwrap(), base).into_iter().map(|(k, _)| k.to_string()).collect() };
        v.dedup();
        return refuse(s, Refusal::Instances(v)).await;
    }
    let mut frame_bytes = hb.to_vec();
    frame_bytes.extend_from_slice(&payload);
    // The name looked up: the Hello's, or its bare api after an instance miss (below).
    let mut lookup = hello.api.clone();
    let mut fell_back = false;
    let deadline = tokio::time::Instant::now() + crate::SPAWN_WAIT;
    let mut spawned = false;
    let mut hold: Option<tokio::time::Instant> = None;
    loop {
        let changed = reg.changed.notified();
        let (pick, others, wire3) = {
            let m = reg.cells.lock().unwrap();
            let v: Vec<(&str, &Cell)> = reach(&m, &lookup);
            // every name this Hello may reach counts as used, marked under the cells lock: the idle sweep re-checks
            // under the same lock, so it never stops a cell between this pick and the handoff below
            {
                let mut i = reg.idle.lock().unwrap();
                v.iter().for_each(|(k, _)| i.touch(k));
            }
            // Only processes that speak the caller's schema; an unparsable registration is taken on trust.
            // schema 0 = the caller declared no schema (a liveness/health or index probe): it routes to any running
            // process and is never drift. A typed caller always sends its real schema hash.
            let (fit, other): (Vec<(&str, &Cell)>, Vec<(&str, &Cell)>) =
                v.into_iter().partition(|(_, c)| hello.schema == 0 || u64::from_str_radix(&c.schema, 16).map_or(true, |h| h == hello.schema) || c.accepts.contains(&hello.schema));
            // Round robin over the processes of this cell on this machine.
            let n = reg.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as usize;
            let pick = (!fit.is_empty()).then(|| fit.iter().map(|(k, c)| (k.to_string(), c.id, c.ctl.clone())).cycle().skip(n % fit.len()).take(fit.len()).collect::<Vec<_>>());
            // none speaks it whole: a caller with an op table may go to a wire-3 process, which checks it op by op,
            // but only when no drift update is coming (below)
            let wire3: Vec<(String, u64, Arc<UnixStream>)> = if caller_ops.is_empty() { vec![] } else { other.iter().filter(|(_, c)| c.wire >= 3 && c.ops.iter().any(|o| caller_ops.contains(o))).map(|(k, c)| (k.to_string(), c.id, c.ctl.clone())).collect() };
            let mut others: Vec<String> = other.iter().map(|(_, c)| c.schema.clone()).collect();
            others.sort();
            others.dedup();
            (pick, others, wire3)
        };
        let (mut pick, others, wire3) = (pick, others, wire3);
        // Instance miss: no process of `<api>#<name>` here at all. A Hello that may spawn (a caller's last step, after
        // the finder and the mesh peers) starts that instance when this machine has its cell.toml, else goes to any
        // process of the bare api, round robin. A Hello that may not spawn is refused NoCell, so the caller goes on to
        // the machine that runs the instance instead of being handed another one.
        if pick.is_none() && others.is_empty() && !fell_back && !spawned && hello.spawn && crate::instance_of(&lookup).is_some() {
            let l2 = lookup.clone();
            let here = tokio::task::spawn_blocking(move || crate::find_manifest(&l2).is_some()).await.unwrap_or(false);
            if !here {
                lookup = crate::base_api(&hello.api).to_string();
                fell_back = true;
                crate::emit("instance-miss", &hello.api, &format!("no {} here: any {lookup}", hello.api));
                continue;
            }
        }
        if pick.is_none() && !others.is_empty() && fell_back {
            // processes of the bare api run but none speaks the caller's schema: not a drift of the instance asked for
            return refuse(s, Refusal::NoCell(format!("{}: not running here; {lookup} runs here only at other schemas", hello.api))).await;
        }
        if pick.is_none() && !others.is_empty() {
            // Schema drift: the cell runs, but not with the caller's schema (door/drift.rs).
            let st = drift::seen(&reg, &hello.api, hello.schema, &others, peer);
            if st.pending() && hold.is_none() && ext.wait_ms >= 5_000 {
                // a caller on its waiting retry: hold its Hello until a fitting build registers (2 s margin)
                hold = Some(tokio::time::Instant::now() + std::time::Duration::from_millis(ext.wait_ms as u64 - 2_000));
            }
            match hold {
                Some(until) if st.pending() && tokio::time::Instant::now() < until => {
                    let _ = tokio::time::timeout_at(until, changed).await;
                    continue;
                }
                // no update is coming (caller-stale, needs a human, unknown, rate-limited): op by op. "updated to" means a
                // fitting build is about to register, so that caller keeps the refusal and its retry
                _ if !st.pending() && !st.word().starts_with("updated") && !wire3.is_empty() => pick = Some(wire3),
                _ => {
                    let ours = u64::from_str_radix(&others[0], 16).unwrap_or(0);
                    let r = if ext.wire >= 2 {
                        Refusal::SchemaAt { ours, theirs: hello.schema, api: hello.api.clone(), update: st.word() }
                    } else {
                        Refusal::Schema { ours, theirs: hello.schema, api: hello.api.clone() }
                    };
                    return refuse(s, r).await;
                }
            }
        }
        for (key, id, ctl) in pick.unwrap_or_default() {
            if handoff(&ctl, s.as_raw_fd(), &frame_bytes).await.is_ok() {
                return; // dropping `s` closes only the door's copy of the socket
            }
            let mut m = reg.cells.lock().unwrap();
            if let Some(v) = m.get_mut(&key) {
                v.retain(|c| c.id != id);
            }
        }
        // Stopped here for idleness (door/idle.rs): any Hello starts it again, also one that may not spawn (a mesh
        // peer's or the finder's dial) and without the spawn gate. The cell ran and answered such callers before the
        // door stopped it; the stop must not change who reaches it. The cell's own gate still checks every op.
        if !spawned {
            let wake = reg.idle.lock().unwrap().to_wake(&lookup);
            if !wake.is_empty() {
                spawned = true;
                crate::emit("idle-wake", &lookup, &wake.join(" "));
                let r2 = reg.clone();
                let t0 = std::time::Instant::now();
                let r = tokio::task::spawn_blocking(move || {
                    let running = move |a: &str| running_in(&r2.cells.lock().unwrap(), a);
                    wake.iter().map(|a| crate::ensure(a, &running)).collect::<Result<Vec<_>, _>>().map(|v| v.join("; "))
                })
                .await
                .unwrap_or_else(|e| Err(e.to_string()));
                match r {
                    Ok(msg) if msg.contains("reproducing") || msg.contains("building") => return refuse(s, Refusal::NoCell(msg)).await,
                    Ok(msg) => eprintln!("ce-door: wake {lookup} ({} ms to start): {msg}", t0.elapsed().as_millis()),
                    Err(e) => return refuse(s, Refusal::NoCell(e)).await,
                }
            }
        }
        if !hello.spawn && !spawned {
            return refuse(s, Refusal::NoCell(format!("{}: not running here", hello.api))).await;
        }
        if !spawned {
            spawned = true;
            if let Some(g) = &reg.spawn_gate {
                if let Err(e) = g(&hello) {
                    return refuse(s, Refusal::NoCell(format!("{}: not running here, and may not start it: {e}", hello.api))).await;
                }
            }
            let (r2, api) = (reg.clone(), lookup.clone());
            let running = move |a: &str| running_in(&r2.cells.lock().unwrap(), a);
            let r = tokio::task::spawn_blocking(move || crate::ensure(&api, &running)).await.unwrap_or_else(|e| Err(e.to_string()));
            match r {
                Ok(msg) if msg.contains("reproducing") || msg.contains("building") => return refuse(s, Refusal::NoCell(msg)).await,
                Ok(_) => {}
                Err(e) => return refuse(s, Refusal::NoCell(e)).await,
            }
        }
        if tokio::time::timeout_at(deadline, changed).await.is_err() {
            return refuse(s, Refusal::NoCell(format!("{}: started but did not register in {:?}", hello.api, crate::SPAWN_WAIT))).await;
        }
    }
}

async fn handoff(ctl: &UnixStream, fd: RawFd, hello: &[u8]) -> std::io::Result<()> {
    let len = (hello.len() as u32).to_le_bytes();
    loop {
        ctl.writable().await?;
        let r = ctl.try_io(Interest::WRITABLE, || {
            let iov = [IoSlice::new(&len), IoSlice::new(hello)];
            let fds = [fd];
            let cmsg = [ControlMessage::ScmRights(&fds)];
            sendmsg::<()>(ctl.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None).map_err(std::io::Error::from)
        });
        match r {
            Ok(n) if n == 4 + hello.len() => return Ok(()),
            Ok(_) => return Err(std::io::Error::other("short handoff")),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

impl<A: Api> Server<A> {
    /// Serve through this machine's door: register, then take every connection the door hands over.
    /// Many processes of the same cell may register; the door spreads connections over them.
    pub async fn serve_door(self) -> Result<(), WireError> {
        self.serve_door_as("").await
    }

    /// [`Self::serve_door`] as instance `name` of the api: registers `<api>#<name>` (`obs.source#wx.metar`), so a
    /// Hello for that instance reaches only this cell and a Hello for the bare api reaches it or any other instance.
    /// An empty `name` is [`Self::serve_door`]. The schema and the rights stay the api's.
    pub async fn serve_door_as(self, name: &str) -> Result<(), WireError> {
        let key = crate::instance_key(A::NAME, name);
        if !crate::valid_key(&key) {
            return Err(WireError::Io(format!("{key}: not a valid instance name")));
        }
        let inner: Arc<Inner<A>> = self.into_inner();
        raise_nofile();
        sigterm_routine(&inner);
        let mut ctl = UnixStream::connect(door_sock()).await.map_err(|e| WireError::Io(format!("door {}: {e}", door_sock().display())))?;
        ctl.write_all(format!("REGISTER {} {:016x} {}{}{} wire={}{}{}\n", key, A::SCHEMA, std::process::id(), crate::rev_field(), crate::adapt::accepts_field::<A>(&inner.olders), crate::WIRE, crate::ops_field::<A>(), crate::apo_field(inner.apoptosis.as_ref().map_or(crate::APOPTOSIS_MS, |a| a.0))).as_bytes())
            .await
            .map_err(|e| WireError::Io(e.to_string()))?;
        let mut bad = 0u32;
        loop {
            // one handoff the kernel could not complete (ENOBUFS: the fd did not fit under RLIMIT_NOFILE, so it
            // arrived truncated) loses that one caller, who retries; it never ends the cell. A cell with over
            // 1,000 clients died here under 50 concurrent submits before this. A door that
            // closed, or a run of failures, still ends it.
            let (fd, hello) = match recv_handoff(&ctl).await {
                Ok(FromDoor::Conn(fd, hello)) => {
                    bad = 0;
                    (fd, hello)
                }
                // the door is about to stop this process: the dying routine runs, its answer goes back, then the
                // door closes the registration and the next read ends the loop
                Ok(FromDoor::Apoptosis(req)) => {
                    let r = die(&inner, postcard::from_bytes(&req).unwrap_or_default()).await;
                    let _ = ctl.write_all(&crate::apo_frame(0, &r)).await;
                    continue;
                }
                Err(e) if e.kind() != std::io::ErrorKind::UnexpectedEof && bad < 100 => {
                    bad += 1;
                    eprintln!("ce-wire {key}: dropped one handoff: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    continue;
                }
                Err(e) => return Err(WireError::Io(e.to_string())),
            };
            // SAFETY: the fd was just received via SCM_RIGHTS and is owned by nobody else in this process.
            let std_s = unsafe { std::net::TcpStream::from_raw_fd(fd) };
            std_s.set_nonblocking(true).map_err(|e| WireError::Io(e.to_string()))?;
            let s = TcpStream::from_std(std_s).map_err(|e| WireError::Io(e.to_string()))?;
            inner.clone().spawn_conn(s, Some(hello));
        }
    }
}

/// Lift this process's soft open-file limit to its hard limit, once. A cell holding a client per peer (a
/// farm.manager over 1,000 printer.cells) passes the common 1,024 soft default; the hard limit is usually far
/// higher (1,048,576 on a typical Linux host). Best effort: a failure leaves the limit as it was.
pub fn raise_nofile() {
    use nix::sys::resource::{getrlimit, setrlimit, Resource};
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if let Ok((soft, hard)) = getrlimit(Resource::RLIMIT_NOFILE) {
            if soft < hard {
                let _ = setrlimit(Resource::RLIMIT_NOFILE, hard, hard);
            }
        }
    });
}

// Linux sets close-on-exec atomically on the received fd; macOS has no MSG_CMSG_CLOEXEC, so it is set right after.
#[cfg(target_os = "linux")]
const RECV_FLAGS: MsgFlags = MsgFlags::MSG_CMSG_CLOEXEC;
#[cfg(not(target_os = "linux"))]
const RECV_FLAGS: MsgFlags = MsgFlags::empty();

/// What the door sends a cell on its registration socket.
enum FromDoor {
    /// A caller's TCP socket and its Hello frame.
    Conn(RawFd, Vec<u8>),
    /// An [`crate::ApoptosisReq`] (postcard): the door is about to stop this process.
    Apoptosis(Vec<u8>),
}

/// Set once the dying routine ran (door request or SIGTERM), so it runs once per process.
static DIED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Run the cell's dying routine once, within its deadline: what it saved, or why not. No routine: nothing to save.
async fn die<A: Api>(inner: &Inner<A>, req: crate::ApoptosisReq) -> Result<crate::Saved, String> {
    if DIED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return Err("the dying routine already ran".into());
    }
    let Some((ms, f)) = inner.apoptosis.clone() else { return Ok(crate::Saved::default()) };
    let ms = if req.deadline_ms == 0 { ms } else { req.deadline_ms.min(ms) };
    match tokio::time::timeout(std::time::Duration::from_millis(ms as u64), f(req)).await {
        Ok(r) => r,
        Err(_) => Err(format!("not done in {ms} ms")),
    }
}

/// SIGTERM (systemd, `kill`, the door after its 5 s grace) runs the dying routine, then the process exits 0. Only a
/// cell that set a routine gets the handler: without one SIGTERM ends it as before.
pub(crate) fn sigterm_routine<A: Api>(inner: &Arc<Inner<A>>) {
    if inner.apoptosis.is_none() {
        return;
    }
    static ONCE: std::sync::Once = std::sync::Once::new();
    let inner = inner.clone();
    ONCE.call_once(move || {
        let Ok(mut sig) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) else { return };
        tokio::spawn(async move {
            if sig.recv().await.is_some() {
                let r = die(&inner, crate::ApoptosisReq { reason: "SIGTERM".into(), deadline_ms: 0 }).await;
                eprintln!("ce-wire {}: SIGTERM: {r:?}", A::NAME);
                std::process::exit(0);
            }
        });
    });
}

async fn recv_handoff(ctl: &UnixStream) -> std::io::Result<FromDoor> {
    let mut buf = vec![0u8; 4 + 64 * 1024];
    let (n, fd) = loop {
        ctl.readable().await?;
        let r = ctl.try_io(Interest::READABLE, || {
            let mut cspace = nix::cmsg_space!([RawFd; 1]);
            let mut iov = [IoSliceMut::new(&mut buf)];
            let msg = recvmsg::<()>(ctl.as_raw_fd(), &mut iov, Some(&mut cspace), RECV_FLAGS)
                .map_err(std::io::Error::from)?;
            let mut fd = None;
            for c in msg.cmsgs().map_err(std::io::Error::from)? {
                if let ControlMessageOwned::ScmRights(v) = c {
                    fd = v.first().copied();
                }
            }
            Ok((msg.bytes, fd))
        });
        match r {
            Ok(x) => break x,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    };
    if n == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "door closed"));
    }
    let Some(fd) = fd else { return apoptosis_req(ctl, &mut buf, n).await };
    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: fd was just received and is owned by this function's caller-to-be; F_SETFD only sets a flag.
        unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFD, nix::libc::FD_CLOEXEC) };
    }
    if n < 4 {
        return Err(std::io::Error::other("short handoff header"));
    }
    let len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
    if len > 64 * 1024 {
        return Err(std::io::Error::other("handoff too big"));
    }
    let mut got = n;
    while got < 4 + len {
        ctl.readable().await?;
        match ctl.try_read(&mut buf[got..4 + len]) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "door closed mid handoff")),
            Ok(k) => got += k,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(FromDoor::Conn(fd, buf[4..4 + len].to_vec()))
}

/// A message without a socket: only an apoptosis request (length word marked with [`crate::APO_MARK`]) is one.
async fn apoptosis_req(ctl: &UnixStream, buf: &mut [u8], n: usize) -> std::io::Result<FromDoor> {
    let word = if n >= 4 { u32::from_le_bytes(buf[..4].try_into().unwrap()) } else { 0 };
    if word & crate::APO_MARK == 0 {
        return Err(std::io::Error::other("handoff without a socket"));
    }
    let len = (word & !crate::APO_MARK) as usize;
    if len > 64 * 1024 {
        return Err(std::io::Error::other("apoptosis request too big"));
    }
    let mut got = n;
    while got < 4 + len {
        ctl.readable().await?;
        match ctl.try_read(&mut buf[got..4 + len]) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "door closed mid request")),
            Ok(k) => got += k,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(FromDoor::Apoptosis(buf[4..4 + len].to_vec()))
}


/// Tell the ce node DHT this machine serves `wire:<api>` (re-sent every 5 min while a process is registered). An
/// instance `<api>#<name>` is advertised under both `wire:<api>#<name>` and `wire:<api>`, so a caller finds the one
/// instance or any process of the api.
fn advertise(key: &str) {
    let base = crate::base_api(key);
    for k in std::iter::once(key).chain((base != key).then_some(base)) {
        let ok = crate::name::ce_node_http("POST", "/discovery/advertise", Some(&format!("{{\"service\":\"wire:{k}\"}}"))).is_some();
        // One miss under load is retried by the next 5-min cycle and is not an error (two
        // single misses while the node answered /status in 15 ms were reported as faults). Two cycles in a row is.
        match advertise_misses(k, ok) {
            0 => {}
            1 => println!("ce-door: advertise wire:{k} not taken this time; next try in 5 min"),
            n => eprintln!("ce-door: advertise wire:{k} failed {n} times in a row (ce node down?)"),
        }
    }
}

/// Consecutive advertise misses for `key` after this attempt (0 when it succeeded).
fn advertise_misses(key: &str, ok: bool) -> u32 {
    static MISSES: std::sync::Mutex<Option<std::collections::HashMap<String, u32>>> = std::sync::Mutex::new(None);
    let mut g = MISSES.lock().unwrap();
    let m = g.get_or_insert_with(Default::default);
    if ok {
        m.remove(key);
        return 0;
    }
    let n = m.entry(key.to_string()).or_insert(0);
    *n += 1;
    *n
}

/// Rewrite `peers_file()` from every underlay network `$CE_NET` enables (`underlay.rs`): ce-scale (`netmesh peers`,
/// only when NETMESH_CONTROL is set), tailscale, netbird, `peers.static`. The old file stays when no network has a peer.
fn refresh_peers() {
    crate::underlay::refresh_peers_file();
}

#[cfg(test)]
mod tests {
    #[test]
    fn one_advertise_miss_is_not_a_fault_two_in_a_row_are() {
        assert_eq!(super::advertise_misses("t.adv", false), 1);
        assert_eq!(super::advertise_misses("t.adv", false), 2);
        assert_eq!(super::advertise_misses("t.adv", true), 0);
        assert_eq!(super::advertise_misses("t.adv", false), 1);
        assert_eq!(super::advertise_misses("t.other", true), 0);
    }
}
