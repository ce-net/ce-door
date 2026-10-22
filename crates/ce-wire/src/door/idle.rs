//! Scale to zero: cells nobody uses should not waste resources, and should start quickly as soon as
//! someone needs them. Measured before this: 265 cells registered, 149 door children holding 2.3 GB, 682 MB free of
//! 16 GB.
//!
//! The door stops a cell it started itself once nobody has used it for `CE_DOOR_IDLE_S` seconds (default 900, 0 = off).
//! "Used" is any of: a Hello the door routed to it, an open TCP connection in the process (a caller's stream, or a link
//! or Watch the cell holds to another cell), CPU time it spent since the last look (background work), or a child
//! process. It stays up, whatever the idle time, when:
//! - its cell.toml says `keep = true` or `idle_stop = false`, or its kind is not one of [`crate::IDLE_STOP_KINDS`]
//!   (`idle_stop = true` opts any kind in);
//! - it is in the door's autostart file (the feeds and watchers this machine always runs);
//! - the door could not start it again: no cell.toml here, `[launch] by` a supervisor, binary not built, needs unmet;
//! - a process of it was not started by this door (systemd, launchd, a shell), or `/proc` cannot be read (not Linux);
//! - it serves a socket of its own (a TCP or Unix listener, an unconnected UDP port): traffic there never passes the
//!   door, so the door could not wake it.
//!
//! A stopped cell is out of the registry like `ce-door stop`, and remembered: the next Hello for it starts it again,
//! also a Hello that may not spawn (a mesh peer's or the finder's dial) and without the spawn gate, because the door
//! stopping it must be invisible to every caller that reached it before. `ce-door stop` / `stop-owner` forget it.
//! Control line `IDLE`: `<name> <idle s> <stoppable|keep: why>` per registered cell, then `stopped <names>`.
use super::{descends_from, stop_cells, Cell, Registry};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const IDLE_DEFAULT_S: u64 = 900;

/// `$CE_DOOR_IDLE_S` (seconds, 0 = never stop an idle cell), else [`IDLE_DEFAULT_S`].
pub fn idle_after() -> Duration {
    Duration::from_secs(std::env::var("CE_DOOR_IDLE_S").ok().and_then(|s| s.trim().parse().ok()).unwrap_or(IDLE_DEFAULT_S))
}

#[derive(Default)]
pub(super) struct Idle {
    /// Per registered name: the last time it was used (routed a Hello, registered, held a connection, used CPU).
    used: HashMap<String, Instant>,
    /// Per registered name: the CPU ticks (utime + stime, all its processes) at the last look.
    cpu: HashMap<String, u64>,
    /// Per registered name: the cell.toml verdict for the processes (ids) it was computed for.
    policy: HashMap<String, (Vec<u64>, Result<(), String>)>,
    /// Per registered name: why it was kept at the last look (for `IDLE`).
    why: HashMap<String, String>,
    /// Names the door stopped for idleness: a Hello for one starts it again.
    stopped: HashSet<String>,
    /// Where `stopped` is kept across door restarts (`idle-stopped` beside the registration socket). A restart forgot
    /// them and a Hello that may not spawn got NoCell (an idle-stopped cell
    /// stayed down after a door restart until it was placed by hand). None = not kept (tests).
    file: Option<std::path::PathBuf>,
}

impl Idle {
    /// A Hello reached `name` (call with the registry's cells lock held, so a sweep never stops a cell between the
    /// pick and the handoff).
    pub(super) fn touch(&mut self, name: &str) {
        self.used.insert(name.to_string(), Instant::now());
    }

    /// The stopped names kept in `file` by an earlier door; from now on every change is written there.
    pub(super) fn keep_in(&mut self, file: std::path::PathBuf) {
        if let Ok(t) = std::fs::read_to_string(&file) {
            self.stopped.extend(t.lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from));
        }
        self.file = Some(file);
    }

    fn save(&self) {
        let Some(f) = &self.file else { return };
        let mut v: Vec<&String> = self.stopped.iter().collect();
        v.sort();
        let t: String = v.iter().map(|n| format!("{n}\n")).collect();
        let tmp = f.with_extension("tmp");
        if std::fs::write(&tmp, t).and_then(|_| std::fs::rename(&tmp, f)).is_err() {
            eprintln!("ce-door: could not keep the idle-stopped names in {}", f.display());
        }
    }

    /// A process of `name` registered: it is in use and no longer stopped.
    pub(super) fn registered(&mut self, name: &str) {
        self.touch(name);
        if self.stopped.remove(name) {
            self.save();
        }
    }

    /// `ce-door stop` (or stop-owner): a stopped cell stays down, so it is no longer woken by a Hello.
    pub(super) fn forget(&mut self, name: &str) -> bool {
        let was = self.stopped.remove(name);
        if was {
            self.save();
        }
        was
    }

    pub(super) fn stopped(&self) -> impl Iterator<Item = &String> {
        self.stopped.iter()
    }

    /// The idle-stopped names a Hello for `lookup` wakes: the name itself, and for a bare api its stopped instances.
    pub(super) fn to_wake(&self, lookup: &str) -> Vec<String> {
        let bare = crate::instance_of(lookup).is_none();
        let mut v: Vec<String> = self.stopped.iter().filter(|k| k.as_str() == lookup || (bare && crate::base_api(k) == lookup)).cloned().collect();
        v.sort();
        v
    }
}

/// What a look at one registered name found.
#[derive(Debug, PartialEq)]
enum Verdict {
    /// Not idle long enough to check: only its CPU ticks were read.
    Ticks(u64),
    /// Never stopped (the reason).
    Keep(String),
    /// In use right now (an open connection, a child process); its ticks.
    Busy(u64, String),
    /// Nothing holds it; its ticks.
    Quiet(u64),
}

/// Every `min(idle / 4, 60 s)` (at least 1 s): look at every registered cell, stop the ones idle for `after`.
pub(super) async fn sweep_loop(reg: Arc<Registry>) {
    let after = reg.idle_after;
    if after.is_zero() {
        return;
    }
    let every = (after / 4).clamp(Duration::from_secs(1), Duration::from_secs(60));
    loop {
        tokio::time::sleep(every).await;
        sweep(&reg).await;
    }
}

async fn sweep(reg: &Arc<Registry>) {
    let after = reg.idle_after;
    let names: Vec<(String, Vec<(u64, u32)>)> = reg.cells.lock().unwrap().iter().map(|(k, v)| (k.clone(), v.iter().map(|c| (c.id, c.pid)).collect())).collect();
    let due: HashSet<String> = {
        let mut i = reg.idle.lock().unwrap();
        let live: HashSet<&String> = names.iter().map(|(k, _)| k).collect();
        i.used.retain(|k, _| live.contains(k));
        i.cpu.retain(|k, _| live.contains(k));
        i.policy.retain(|k, _| live.contains(k));
        i.why.retain(|k, _| live.contains(k));
        let now = Instant::now();
        names.iter().filter(|(k, _)| *i.used.entry(k.clone()).or_insert(now) + after <= now).map(|(k, _)| k.clone()).collect()
    };
    let cached: HashMap<String, (Vec<u64>, Result<(), String>)> = {
        let i = reg.idle.lock().unwrap();
        due.iter().filter_map(|k| i.policy.get(k).map(|p| (k.clone(), p.clone()))).collect()
    };
    let (n2, d2) = (names.clone(), due.clone());
    let Ok(looks) = tokio::task::spawn_blocking(move || look(&n2, &d2, cached)).await else { return };
    let mut gone: Vec<(String, Vec<Cell>)> = Vec::new();
    {
        let mut m = reg.cells.lock().unwrap();
        let mut i = reg.idle.lock().unwrap();
        let now = Instant::now();
        for (name, ids, verdict, policy) in looks {
            if let Some(p) = policy {
                i.policy.insert(name.clone(), (ids.clone(), p));
            }
            let ticks = match &verdict {
                Verdict::Ticks(t) | Verdict::Busy(t, _) | Verdict::Quiet(t) => Some(*t),
                Verdict::Keep(_) => None,
            };
            // CPU spent since the last look is use (background work); the first look only sets the mark
            let moved = ticks.is_some_and(|t| i.cpu.insert(name.clone(), t).is_some_and(|old| old != t));
            if moved {
                i.touch(&name);
                i.why.insert(name.clone(), "busy: used CPU".into());
            }
            match verdict {
                Verdict::Ticks(_) => continue,
                Verdict::Keep(why) => {
                    // looked at again only after another idle period
                    i.touch(&name);
                    i.why.insert(name, format!("keep: {why}"));
                    continue;
                }
                Verdict::Busy(_, why) => {
                    i.touch(&name);
                    i.why.insert(name, format!("busy: {why}"));
                    continue;
                }
                Verdict::Quiet(_) if moved => continue,
                Verdict::Quiet(_) => {}
            }
            // re-checked under the cells lock: a Hello routed since the look touched it; a new or replaced process
            // was not looked at
            let fresh = i.used.get(&name).is_some_and(|t| *t + after > now);
            let same = m.get(&name).is_some_and(|v| v.iter().map(|c| c.id).collect::<Vec<_>>() == ids);
            if fresh || !same {
                continue;
            }
            let cells = m.remove(&name).unwrap_or_default();
            i.used.remove(&name);
            i.cpu.remove(&name);
            i.policy.remove(&name);
            i.why.remove(&name);
            i.stopped.insert(name.clone());
            gone.push((name, cells));
        }
        if !gone.is_empty() {
            i.save();
        }
    }
    if gone.is_empty() {
        return;
    }
    reg.changed.notify_waiters();
    for (name, cells) in gone {
        eprintln!("ce-door: {name} idle {} s: stopping {} process(es); the next call starts it", after.as_secs(), cells.len());
        crate::emit("idle-stop", &name, &format!("{} process(es), idle {} s", cells.len(), after.as_secs()));
        // the spawn that started it is long over: without this a wake within SPAWN_WINDOW would attach to it
        crate::name::spawned(&name);
        let why = format!("idle {} s", after.as_secs());
        tokio::task::spawn_blocking(move || stop_cells(cells, &why));
    }
}

/// The blocking part of a sweep: CPU ticks for every name, and for the `due` ones the full check. Each result carries
/// the process ids it saw and a freshly computed cell.toml verdict to cache (None when `cached` had it).
#[allow(clippy::type_complexity)]
fn look(
    names: &[(String, Vec<(u64, u32)>)],
    due: &HashSet<String>,
    cached: HashMap<String, (Vec<u64>, Result<(), String>)>,
) -> Vec<(String, Vec<u64>, Verdict, Option<Result<(), String>>)> {
    let me = std::process::id();
    let auto = if due.is_empty() { HashSet::new() } else { autostart() };
    let kids = if due.is_empty() { HashMap::new() } else { children() };
    let mut out = Vec::new();
    for (name, cells) in names {
        let ids: Vec<u64> = cells.iter().map(|(id, _)| *id).collect();
        let ticks: Option<u64> = cells.iter().map(|(_, p)| cpu_ticks(*p)).sum();
        let Some(t) = ticks else {
            out.push((name.clone(), ids, Verdict::Keep("its /proc cannot be read".into()), None));
            continue;
        };
        if !due.contains(name) {
            out.push((name.clone(), ids, Verdict::Ticks(t), None));
            continue;
        }
        let (policy, fresh) = match cached.get(name) {
            Some((c, p)) if *c == ids => (p.clone(), None),
            _ => {
                let p = manifest_policy(name);
                (p.clone(), Some(p))
            }
        };
        let v = if auto.contains(name) {
            Verdict::Keep("in the door's autostart file".into())
        } else if let Err(why) = policy {
            Verdict::Keep(why)
        } else {
            process_verdict(cells, me, &kids, t)
        };
        out.push((name.clone(), ids, v, fresh));
    }
    out
}

/// The cell.toml part of the verdict: stoppable only when the door could start it again.
fn manifest_policy(name: &str) -> Result<(), String> {
    let m = crate::find_manifest(name).ok_or("no cell.toml here: the door could not start it again")?;
    if let Some(by) = crate::launched_by(&m) {
        return Err(format!("started by {by}"));
    }
    if let Some(why) = crate::unmet(&m) {
        return Err(format!("not runnable here: {why}"));
    }
    if crate::name::unbuilt(&m) {
        return Err("binary not built: a start would build first".into());
    }
    crate::idle_stoppable(&std::fs::read_to_string(&m).map_err(|e| e.to_string())?)
}

fn process_verdict(cells: &[(u64, u32)], me: u32, kids: &HashMap<u32, u32>, ticks: u64) -> Verdict {
    for (_, pid) in cells {
        if *pid == 0 || descends_from(*pid, me) != Some(true) {
            return Verdict::Keep(format!("pid {pid} was not started by this door"));
        }
        let Some(s) = sockets(*pid) else { return Verdict::Keep(format!("pid {pid}: sockets cannot be read")) };
        if let Some(what) = s.serves {
            return Verdict::Keep(format!("pid {pid} {what}: the door never sees that traffic"));
        }
        if s.conns > 0 {
            return Verdict::Busy(ticks, format!("pid {pid} holds {} connection(s)", s.conns));
        }
        if let Some(n) = kids.get(pid) {
            return Verdict::Busy(ticks, format!("pid {pid} has {n} child process(es)"));
        }
    }
    Verdict::Quiet(ticks)
}

/// The door's autostart file (`$CE_DOOR_AUTOSTART` or `~/.config/ce-wire/autostart`, the same the `ce-door` binary
/// places from): one name per line.
fn autostart() -> HashSet<String> {
    let f = std::env::var("CE_DOOR_AUTOSTART").map(std::path::PathBuf::from).unwrap_or_else(|_| {
        std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config/ce-wire/autostart")
    });
    std::fs::read_to_string(f).unwrap_or_default().lines().map(crate::strip_comment).map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect()
}

/// utime + stime of `pid` in clock ticks; None where /proc cannot be read (a gone pid, or not Linux).
fn cpu_ticks(pid: u32) -> Option<u64> {
    let st = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    ticks_of(&st)
}

fn ticks_of(stat: &str) -> Option<u64> {
    // pid (comm) state ppid ...: utime and stime are fields 14 and 15, so 12th and 13th after the comm
    let f: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    Some(f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?)
}

/// Live child processes per parent pid, from one pass over /proc.
fn children() -> HashMap<u32, u32> {
    let mut m = HashMap::new();
    for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Some(st) = e.file_name().to_str().filter(|n| n.bytes().all(|b| b.is_ascii_digit())).and_then(|n| std::fs::read_to_string(format!("/proc/{n}/stat")).ok()) else { continue };
        let Some(rest) = st.rsplit_once(')').map(|r| r.1) else { continue };
        let mut f = rest.split_whitespace();
        // a zombie child is already over (the door reaps it soon); it holds nothing
        if f.next() == Some("Z") {
            continue;
        }
        if let Some(pp) = f.next().and_then(|p| p.parse().ok()) {
            *m.entry(pp).or_insert(0) += 1;
        }
    }
    m
}

#[derive(Debug, Default, PartialEq)]
struct Socks {
    /// TCP connections open or opening (established, connecting, half closed by the peer).
    conns: usize,
    /// A socket it serves outside the door, when it has one.
    serves: Option<String>,
}

/// The sockets `pid` holds, from its fds and its network namespace's tables.
fn sockets(pid: u32) -> Option<Socks> {
    let mut inodes = HashSet::new();
    for e in std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?.flatten() {
        if let Some(n) = std::fs::read_link(e.path()).ok().and_then(|l| l.to_str().and_then(|s| s.strip_prefix("socket:[")?.strip_suffix(']')?.parse::<u64>().ok())) {
            inodes.insert(n);
        }
    }
    let mut s = Socks::default();
    if inodes.is_empty() {
        return Some(s);
    }
    for (f, tcp) in [("tcp", true), ("tcp6", true), ("udp", false), ("udp6", false)] {
        if let Ok(t) = std::fs::read_to_string(format!("/proc/{pid}/net/{f}")) {
            scan_inet(&t, &inodes, tcp, &mut s);
        }
    }
    if let Ok(t) = std::fs::read_to_string(format!("/proc/{pid}/net/unix")) {
        scan_unix(&t, &inodes, &mut s);
    }
    Some(s)
}

/// Rows of /proc/net/{tcp,tcp6,udp,udp6} for these socket inodes: `sl local rem st tx:rx tr:when retr uid timeout inode`.
fn scan_inet(table: &str, inodes: &HashSet<u64>, tcp: bool, s: &mut Socks) {
    for l in table.lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        let (Some(local), Some(st), Some(ino)) = (f.get(1), f.get(3), f.get(9).and_then(|i| i.parse::<u64>().ok())) else { continue };
        if !inodes.contains(&ino) {
            continue;
        }
        let port = local.rsplit_once(':').and_then(|(_, p)| u16::from_str_radix(p, 16).ok()).unwrap_or(0);
        match (tcp, *st) {
            // ESTABLISHED, SYN_SENT, SYN_RECV, CLOSE_WAIT
            (true, "01" | "02" | "03" | "08") => s.conns += 1,
            (true, "0A") => s.serves = s.serves.take().or(Some(format!("listens on tcp port {port}"))),
            // unconnected (07) with a port: a UDP server; a connected one (01) is a client's
            (false, "07") if port != 0 => s.serves = s.serves.take().or(Some(format!("binds udp port {port}"))),
            _ => {}
        }
    }
}

/// Rows of /proc/net/unix: `Num RefCount Protocol Flags Type St Inode Path`; flag 0x10000 is a listening socket.
fn scan_unix(table: &str, inodes: &HashSet<u64>, s: &mut Socks) {
    for l in table.lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        let (Some(flags), Some(ino)) = (f.get(3).and_then(|x| u32::from_str_radix(x, 16).ok()), f.get(6).and_then(|i| i.parse::<u64>().ok())) else { continue };
        if inodes.contains(&ino) && flags & 0x10000 != 0 {
            s.serves = s.serves.take().or(Some(format!("listens on unix socket {}", f.get(7).copied().unwrap_or("(unnamed)"))));
        }
    }
}

/// The `IDLE` control answer: per registered name its idle seconds and verdict, then the names stopped for idleness.
pub(super) fn report(reg: &Registry) -> String {
    let names: Vec<String> = reg.cells.lock().unwrap().keys().cloned().collect();
    let i = reg.idle.lock().unwrap();
    let now = Instant::now();
    let mut v: Vec<String> = names
        .iter()
        .map(|k| {
            let idle = i.used.get(k).map_or(0, |t| now.duration_since(*t).as_secs());
            let why = i.why.get(k).cloned().or_else(|| i.policy.get(k).map(|(_, p)| p.clone().map_or_else(|e| format!("keep: {e}"), |()| "stoppable".into())));
            format!("{k} {idle} {}", why.unwrap_or_else(|| "not looked at yet".into()))
        })
        .collect();
    let mut st: Vec<&String> = i.stopped().collect();
    st.sort();
    v.push(format!("idle after {} s{}; stopped: {}", reg.idle_after.as_secs(), if reg.idle_after.is_zero() { " (off)" } else { "" }, st.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" ")));
    v.join("\n")
}

#[cfg(test)]
mod tests {

    #[test]
    fn idle_stopped_names_survive_a_door_restart() {
        let d = std::env::temp_dir().join(format!("idle-keep-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("idle-stopped");
        let _ = std::fs::remove_file(&f);
        let mut a = Idle::default();
        a.keep_in(f.clone());
        a.stopped.insert("org.registry".into());
        a.stopped.insert("twin.world".into());
        a.save();
        let mut b = Idle::default(); // the restarted door
        b.keep_in(f.clone());
        assert_eq!(b.to_wake("org.registry"), vec!["org.registry".to_string()]);
        b.registered("org.registry");
        assert!(b.forget("twin.world"));
        let mut c = Idle::default();
        c.keep_in(f.clone());
        assert!(c.stopped.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    use super::*;

    #[test]
    fn cpu_ticks_are_read_after_the_comm() {
        let st = "4242 (a cell) with) S 1 4242 4242 0 -1 4194560 100 0 0 0 37 5 0 0 20 0 3 0 100 0 0";
        assert_eq!(ticks_of(st), Some(42));
        assert_eq!(ticks_of("garbage"), None);
        assert!(cpu_ticks(std::process::id()).is_some());
    }

    #[test]
    fn sockets_tell_connections_from_servers() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1E14 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 11 1 0 20 4 30 10 -1\n   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12 1 0 100 0 0 10 0\n   2: 0100007F:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 99 1 0 100 0 0 10 0\n";
        let mine: HashSet<u64> = [11].into();
        let mut s = Socks::default();
        scan_inet(tcp, &mine, true, &mut s);
        assert_eq!(s, Socks { conns: 1, serves: None });
        let mine: HashSet<u64> = [11, 12].into();
        let mut s = Socks::default();
        scan_inet(tcp, &mine, true, &mut s);
        assert_eq!(s, Socks { conns: 1, serves: Some("listens on tcp port 8080".into()) });

        let udp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n  1: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 21 2 0 0\n  2: 0100007F:D431 0100007F:0035 01 00000000:00000000 00:00000000 00000000  1000        0 22 2 0 0\n";
        let mut s = Socks::default();
        scan_inet(udp, &[22].into(), false, &mut s);
        assert_eq!(s, Socks::default(), "a connected UDP socket is a client's");
        scan_inet(udp, &[21].into(), false, &mut s);
        assert_eq!(s.serves.as_deref(), Some("binds udp port 5353"));

        let unix = "Num       RefCount Protocol Flags    Type St Inode Path\n0000000000000000: 00000002 00000000 00010000 0001 01 31 /run/user/1000/x.sock\n0000000000000000: 00000003 00000000 00000000 0001 03 32 /var/lib/u/.ce/wire-door.sock\n";
        let mut s = Socks::default();
        scan_unix(unix, &[32].into(), &mut s);
        assert_eq!(s, Socks::default(), "the door's registration socket is a connection, not a server");
        scan_unix(unix, &[31, 32].into(), &mut s);
        assert_eq!(s.serves.as_deref(), Some("listens on unix socket /run/user/1000/x.sock"));
    }

    #[test]
    fn this_process_sockets_are_read() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let s = sockets(std::process::id()).unwrap();
        assert!(s.serves.as_deref().is_some_and(|w| w.starts_with("listens on")), "{s:?}");
        let c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let s = sockets(std::process::id()).unwrap();
        assert!(s.conns >= 1, "{s:?}");
        drop((c, l));
    }

    #[test]
    fn a_hello_wakes_its_stopped_name_and_a_bare_api_its_instances() {
        let mut i = Idle::default();
        for k in ["obs.source#wx.metar", "obs.source#wx.dwd", "obs.sourcex", "a.b"] {
            i.stopped.insert(k.into());
        }
        assert_eq!(i.to_wake("obs.source"), ["obs.source#wx.dwd", "obs.source#wx.metar"]);
        assert_eq!(i.to_wake("obs.source#wx.dwd"), ["obs.source#wx.dwd"]);
        assert_eq!(i.to_wake("a.b"), ["a.b"]);
        assert!(i.to_wake("c.d").is_empty());
        i.registered("a.b");
        assert!(i.to_wake("a.b").is_empty());
        assert!(i.forget("obs.sourcex"));
        assert!(!i.forget("obs.sourcex"));
    }

    #[test]
    fn a_process_the_door_did_not_start_is_kept() {
        // pid 1 is nobody's descendant
        assert!(matches!(process_verdict(&[(1, 1)], std::process::id(), &HashMap::new(), 0), Verdict::Keep(w) if w.contains("not started by this door")));
        assert!(matches!(process_verdict(&[(1, 0)], std::process::id(), &HashMap::new(), 0), Verdict::Keep(_)));
    }
}
