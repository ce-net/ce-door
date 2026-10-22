//! Schema drift at the door: a Hello whose schema no running process of its api has.
//!
//! The door logs it, answers at once, and decides in the background who is stale. Schema hashes have no order, so it
//! asks git: the cell's checkout is fetched (20 s), and the rev the running process was built from is compared with
//! `@{u}`. Behind: the door books a build of `@{u}` through host-room, builds it in a clean worktree in its own cache
//! (never in `~/dev/<repo>`, which people edit), starts it, and stops the old processes only once the new one has
//! registered. At `@{u}`: the caller is stale. A dirty or diverged checkout: a human decides. One check (and so at most
//! one update) per api per 10 min; the result answers every drift of that api meanwhile.
use super::{stop_cells, Cell, Registry};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long a finished check answers for its api (and so the rate limit: one update per api per node per 10 min).
pub const CHECK_TTL: Duration = Duration::from_secs(600);
const FETCH_WAIT: Duration = Duration::from_secs(20);
/// A new build that does not register in this time is stopped; the old processes keep serving.
const REGISTER_WAIT: Duration = Duration::from_secs(60);
/// A queued build that host-room never admits is forgotten after this.
const QUEUE_TTL: Duration = Duration::from_secs(2 * 3600);

#[derive(Clone, Debug, PartialEq)]
pub enum State {
    Checking,
    /// Waiting for host-room: "queued #N", and the job id the admission line must carry.
    Queued { pos: String, job: String, sha: String },
    Updating,
    /// "caller-stale", "updated to <rev>", "needs a human: ...", "unknown: ...".
    Done(String),
}

impl State {
    /// The `update` word in `Refusal::SchemaAt`.
    pub fn word(&self) -> String {
        match self {
            State::Checking => "checking".into(),
            State::Queued { pos, .. } => pos.clone(),
            State::Updating => "updating".into(),
            State::Done(w) if w.starts_with("updated") => "rate-limited".into(),
            State::Done(w) => w.clone(),
        }
    }
    pub fn pending(&self) -> bool {
        matches!(self, State::Checking | State::Queued { .. } | State::Updating)
    }
}

struct Entry {
    state: State,
    at: Instant,
}

static CHECKS: Mutex<Option<HashMap<String, Entry>>> = Mutex::new(None);
/// The rev each api's running build came from, when this door built it.
static REVS: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

fn set(reg: &Registry, api: &str, state: State) {
    crate::emit("schema-drift", api, &format!("{state:?}"));
    CHECKS.lock().unwrap().get_or_insert_with(HashMap::new).insert(api.into(), Entry { state, at: Instant::now() });
    reg.changed.notify_waiters();
}

/// A Hello for `api` with schema `theirs` met only processes with other schemas. Logs it, starts a check when none is
/// fresh, and returns what the door does about it.
pub fn seen(reg: &Arc<Registry>, api: &str, theirs: u64, running: &[String], peer: Option<std::net::SocketAddr>) -> State {
    let mut g = CHECKS.lock().unwrap();
    let m = g.get_or_insert_with(HashMap::new);
    let fresh = m.get(api).filter(|e| match &e.state {
        State::Done(_) => e.at.elapsed() < CHECK_TTL,
        State::Queued { .. } => e.at.elapsed() < QUEUE_TTL,
        _ => true,
    });
    if let Some(e) = fresh {
        return e.state.clone();
    }
    m.insert(api.into(), Entry { state: State::Checking, at: Instant::now() });
    drop(g);
    // Name the caller's peer address so a schema-0 sweeper (or any drifting caller) can be identified and fixed.
    let from = peer.map(|p| format!(" from {p}")).unwrap_or_default();
    crate::emit("schema-drift", api, &format!("caller {theirs:016x}{from}, running {}; checking", running.join(",")));
    eprintln!("ce-door: schema drift {api}: caller {theirs:016x}{from}, running {}", running.join(","));
    let (r, a) = (reg.clone(), api.to_string());
    std::thread::spawn(move || {
        let s = check(&r, &a);
        set(&r, &a, s);
    });
    State::Checking
}

/// The answer for the admission line `BUILD <api> <sha> job=<id>` that host-room writes to the door socket.
pub fn admitted(reg: &Arc<Registry>, api: &str, sha: &str, job: &str) -> String {
    let ok = matches!(
        CHECKS.lock().unwrap().as_ref().and_then(|m| m.get(api)).map(|e| &e.state),
        Some(State::Queued { job: j, sha: s, .. }) if j == job && s == sha
    );
    if !ok {
        return format!("error {api}: no queued update with job {job}");
    }
    set(reg, api, State::Updating);
    let (r, a, s, j) = (reg.clone(), api.to_string(), sha.to_string(), job.to_string());
    std::thread::spawn(move || {
        let done = update_at(&r, &a, &s);
        room(&["done", &lane(&a), "--job", &j]);
        set(&r, &a, done);
    });
    format!("{api}: building {}", short(sha))
}

fn short(sha: &str) -> &str {
    &sha[..sha.len().min(10)]
}

fn lane(api: &str) -> String {
    format!("door.{api}")
}

/// `git` in `dir`, killed after `wait`. -> trimmed stdout.
fn git(dir: &Path, args: &[&str], wait: Duration) -> Result<String, String> {
    run(Command::new("git").arg("-C").arg(dir).args(args), wait).map_err(|e| format!("git {}: {e}", args.join(" ")))
}

fn run(cmd: &mut Command, wait: Duration) -> Result<String, String> {
    let mut ch = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let t = Instant::now();
    loop {
        match ch.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if t.elapsed() < wait => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = ch.kill();
                let _ = ch.wait();
                return Err(format!("no answer in {wait:?}"));
            }
        }
    }
    let o = ch.wait_with_output().map_err(|e| e.to_string())?;
    let out = String::from_utf8_lossy(&o.stdout).trim().to_string();
    if o.status.success() {
        Ok(out)
    } else {
        Err(format!("{}: {}{}", o.status, String::from_utf8_lossy(&o.stderr).trim(), out))
    }
}

/// The rev the running processes were built from: what they registered (`rev=`), else what this door last built,
/// else the checkout's HEAD, which is only a guess (it can be dirty or ahead of what runs) and is logged as one.
fn running_rev(reg: &Registry, api: &str, dir: &Path) -> Result<String, String> {
    let said = reg.cells.lock().unwrap().get(api).and_then(|v| v.iter().find_map(|c| c.rev.clone()));
    if let Some(r) = said.or_else(|| REVS.lock().unwrap().as_ref().and_then(|r| r.get(api).cloned())) {
        return Ok(r);
    }
    let h = git(dir, &["rev-parse", "HEAD"], Duration::from_secs(10))?;
    crate::emit("schema-drift", api, &format!("running rev unknown; guess: checkout HEAD {}", short(&h)));
    Ok(h)
}

/// A finished build of `sha` in the door's cache: reused, never rebuilt (a door restart loop cannot cause a storm).
fn built(api: &str, sha: &str) -> Option<PathBuf> {
    let m = std::fs::read_to_string(build_dir(api, sha).join(".ce-door-built")).ok()?;
    let p = PathBuf::from(m.trim());
    p.is_file().then_some(p)
}

fn build_dir(api: &str, sha: &str) -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".cache/ce-door/builds").join(api).join(short(sha))
}

/// Who is stale. Never builds; books the build when the running cell is behind its upstream.
fn check(reg: &Arc<Registry>, api: &str) -> State {
    let Some(m) = crate::find_manifest(api) else { return State::Done(format!("unknown: no cell.toml for {api} here")) };
    let dir = m.parent().unwrap_or(Path::new(".")).to_path_buf();
    let q = Duration::from_secs(10);
    match git(&dir, &["status", "--porcelain", "--untracked-files=no"], q) {
        Ok(s) if !s.is_empty() => return State::Done(format!("needs a human: {} has uncommitted changes", dir.display())),
        Err(e) => return State::Done(format!("unknown: {e}")),
        Ok(_) => {}
    }
    if let Err(e) = git(&dir, &["fetch", "-q"], FETCH_WAIT) {
        return State::Done(format!("unknown: {e}"));
    }
    let up = match git(&dir, &["rev-parse", "@{u}"], q) {
        Ok(u) => u,
        Err(e) => return State::Done(format!("unknown: no upstream: {e}")),
    };
    let running = match running_rev(reg, api, &dir) {
        Ok(r) => r,
        Err(e) => return State::Done(format!("unknown: {e}")),
    };
    if running == up {
        return State::Done("caller-stale".into());
    }
    if git(&dir, &["merge-base", "--is-ancestor", &running, &up], q).is_err() {
        return State::Done(format!("needs a human: running {} is not behind upstream {} (diverged)", short(&running), short(&up)));
    }
    if built(api, &up).is_some() {
        set(reg, api, State::Updating); // already built here: start it, no room needed
        return update_at(reg, api, &up);
    }
    book(reg, api, &up)
}

/// host-room (Linux) or mac-room (Mac), the shared queue for heavy jobs. `$CE_DOOR_ROOM`: a path, or `none`.
fn room_bin() -> Option<PathBuf> {
    match std::env::var("CE_DOOR_ROOM") {
        Ok(v) if v == "none" => return None,
        Ok(v) if !v.is_empty() => return Some(PathBuf::from(v)),
        _ => {}
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    for b in ["host-room", "mac-room"] {
        if let Some(p) = std::env::split_paths(&path).map(|d| d.join(b)).find(|p| p.is_file()) {
            return Some(p);
        }
    }
    let h = PathBuf::from(std::env::var("HOME").unwrap_or_default()).join("dev/ce-fleet/bin/host-room");
    h.is_file().then_some(h)
}

fn room(args: &[&str]) -> Option<(i32, String)> {
    let b = room_bin()?;
    let o = Command::new(b).args(args).stdin(std::process::Stdio::null()).output().ok()?;
    Some((o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned()))
}

/// Ask host-room for room to build `sha`. GO: build now. Queued: host-room writes `BUILD <api> <sha> job=<id>` to the
/// door socket on admission ([`admitted`]). No host-room on this machine: build now.
fn book(reg: &Arc<Registry>, api: &str, sha: &str) -> State {
    let job = format!("{}-{}", short(sha), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0));
    let prio = std::env::var("CE_DOOR_UPDATE_PRIORITY").unwrap_or_else(|_| "3".into());
    let sock = super::door_sock();
    let line = format!("BUILD {api} {sha} job={job}");
    let why = format!("ce-door: rebuild {api} at {} (schema drift)", short(sha));
    let sock_s = sock.display().to_string();
    let args = ["ask", &lane(api), "heavy", &why, "--priority", &prio, "--job", &job, "--then-sock", &sock_s, "--then-line", &line];
    match room(&args) {
        Some((3, out)) => {
            let pos = out.split("Queued #").nth(1).and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next()).unwrap_or("?");
            State::Queued { pos: format!("queued #{pos}"), job, sha: sha.into() }
        }
        Some((0, _)) => {
            set(reg, api, State::Updating);
            let s = update_at(reg, api, sha);
            room(&["done", &lane(api), "--job", &job]);
            s
        }
        Some((c, out)) => State::Done(format!("unknown: host-room ask exited {c}: {}", out.trim())),
        None => {
            eprintln!("ce-door: no host-room/mac-room here; building {api} now");
            set(reg, api, State::Updating);
            update_at(reg, api, sha)
        }
    }
}

/// Build `sha` of `api`'s repo in `~/.cache/ce-door/builds/<api>/<sha>` (a detached worktree), start it, and stop the
/// old processes once the new one has registered. The old ones serve until then, and keep serving if it fails.
fn update_at(reg: &Arc<Registry>, api: &str, sha: &str) -> State {
    let fail = |e: String| {
        crate::emit("failed", api, &e);
        State::Done(format!("unknown: {e}"))
    };
    let Some(m) = crate::find_manifest(api) else { return fail("no cell.toml".into()) };
    let dir = m.parent().unwrap_or(Path::new(".")).to_path_buf();
    let q = Duration::from_secs(10);
    let top = match git(&dir, &["rev-parse", "--show-toplevel"], q) {
        Ok(t) => PathBuf::from(t),
        Err(e) => return fail(e),
    };
    let Ok(rel) = std::fs::canonicalize(&m).map_err(|_| ()).and_then(|c| c.strip_prefix(std::fs::canonicalize(&top).unwrap_or(top.clone())).map(Path::to_path_buf).map_err(|_| ())) else {
        return fail(format!("{} is outside {}", m.display(), top.display()));
    };
    let wt = build_dir(api, sha);
    if !wt.join(&rel).is_file() {
        let _ = git(&top, &["worktree", "prune"], q);
        let _ = std::fs::create_dir_all(wt.parent().unwrap_or(Path::new("/")));
        if let Err(e) = git(&top, &["worktree", "add", "--detach", &wt.display().to_string(), sha], Duration::from_secs(120)) {
            return fail(e);
        }
    }
    let wm = wt.join(&rel);
    if built(api, sha).is_none() {
        crate::emit("update", api, &format!("build {} at {}", wm.display(), short(sha)));
        if let Err(e) = crate::build(&wm) {
            return fail(e);
        }
        let _ = std::fs::write(wt.join(".ce-door-built"), wm.display().to_string());
    } else {
        crate::emit("update", api, &format!("reuse the build at {}", short(sha)));
    }
    let pid = match crate::spawn_pid(&wm, Some(sha)) {
        Ok(p) => p,
        Err(e) => return fail(format!("{e:?}")),
    };
    let t = Instant::now();
    let new_id = loop {
        if let Some(id) = reg.cells.lock().unwrap().get(api).and_then(|v| v.iter().find(|c| c.pid == pid).map(|c| c.id)) {
            break Some(id);
        }
        if t.elapsed() > REGISTER_WAIT {
            break None;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let Some(new_id) = new_id else {
        use nix::sys::signal::{kill, Signal};
        let _ = kill(nix::unistd::Pid::from_raw(pid as i32), Signal::SIGTERM);
        return fail(format!("the build at {} did not register in {REGISTER_WAIT:?}; the old one keeps serving", short(sha)));
    };
    let old: Vec<Cell> = {
        let mut cells = reg.cells.lock().unwrap();
        let v = cells.entry(api.into()).or_default();
        let (keep, old) = std::mem::take(v).into_iter().partition(|c| c.id == new_id);
        *v = keep;
        old
    };
    crate::emit("stop", api, &format!("{} process(es), replaced by {}", old.len(), short(sha)));
    reg.changed.notify_waiters();
    stop_cells(old, "schema drift update");
    REVS.lock().unwrap().get_or_insert_with(HashMap::new).insert(api.into(), sha.into());
    State::Done(format!("updated to {}", short(sha)))
}
