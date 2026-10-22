//! Call a cell by name (D12a): `Client::<A>::by_name(token)` goes through the doors (`door.rs`): this machine's door,
//! then every net.mesh peer's door, then this machine's door again with "start it". Spawning reads the cell's
//! ceapp.toml `[wire] spawn = [argv]`.
#[cfg(feature = "client")]
use crate::Api;
use crate::WireError;
use std::net::IpAddr;
#[cfg(feature = "client")]
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const SPAWN_WAIT: Duration = Duration::from_secs(10);

/// The peers: `$CE_WIRE_PEERS` (comma separated) or `~/.config/ce-wire/peers`, one `<ip>[:port] [node id hex]` per
/// line, `#` comments (ce-door rewrites that file every 60 s from every underlay network: ce-scale, tailscale, netbird,
/// `peers.static`; `underlay.rs`).
pub fn mesh_peers() -> Vec<IpAddr> {
    mesh_peer_ids().into_iter().map(|(ip, _)| ip).collect()
}

pub fn mesh_peer_ids() -> Vec<(IpAddr, Option<String>)> {
    let raw = std::env::var("CE_WIRE_PEERS").ok().or_else(|| std::fs::read_to_string(peers_file()).ok());
    raw.unwrap_or_default()
        .split(|c| c == ',' || c == '\n')
        .filter_map(|s| {
            let mut w = s.split('#').next()?.split_whitespace();
            let host = w.next()?;
            // an ip, or ip:port with the port ignored (every door listens on the door port); anything else is said,
            // not dropped silently (a "host:port" peer used to fall through to a local spawn)
            let ip = host.parse::<IpAddr>().ok().or_else(|| host.parse::<std::net::SocketAddr>().ok().map(|a| a.ip()));
            if ip.is_none() {
                eprintln!("ce-wire: peer {host:?} is not an ip address; skipped");
            }
            Some((ip?, w.next().map(str::to_string)))
        })
        .collect()
}

pub fn peers_file() -> PathBuf {
    home().join(".config/ce-wire/peers")
}

/// The ce node HTTP API: `$CE_NODE` (host:port) or 127.0.0.1:8844, bearer token from `<ce_data_dir>/api.token`.
pub(crate) fn ce_node_http(method: &str, path: &str, body: Option<&str>) -> Option<String> {
    use std::io::{Read, Write};
    let addr = std::env::var("CE_NODE").unwrap_or_else(|_| "127.0.0.1:8844".into());
    let token = std::fs::read_to_string(ce_data_dir().join("api.token")).unwrap_or_default();
    let mut s = std::net::TcpStream::connect_timeout(&addr.parse().ok()?, Duration::from_millis(300)).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(500))).ok()?;
    let body = body.unwrap_or("");
    write!(s, "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", token.trim(), body.len()).ok()?;
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    let (head, body) = out.split_once("\r\n\r\n")?;
    head.starts_with("HTTP/1.1 2").then(|| body.to_string())
}

/// Node ids (hex) that advertise cell `api` in the ce node's DHT (`wire:<api>`). `None`: the node did not answer.
pub fn find_providers(api: &str) -> Option<Vec<String>> {
    let b = ce_node_http("GET", &format!("/discovery/find/wire:{}", api.replace('#', "%23")), None)?;
    let i = b.find("\"providers\":[")? + 13;
    let list = &b[i..i + b[i..].find(']')?];
    Some(list.split(',').map(|s| s.trim().trim_matches('"').to_string()).filter(|s| !s.is_empty()).collect())
}

/// The mesh peers worth dialing for `api`: those whose node id advertises it, or all of them when the DHT has no
/// answer (node down, peers file without ids).
pub fn candidates(api: &str) -> Vec<IpAddr> {
    let peers = mesh_peer_ids();
    let all = || peers.iter().map(|(ip, _)| *ip).collect();
    match find_providers(api) {
        // Peers without an id (tailscale, netbird) cannot be matched; the ones with ids still narrow the dial.
        Some(p) if !p.is_empty() && peers.iter().any(|(_, id)| id.is_some()) => {
            let v: Vec<IpAddr> = peers.iter().filter(|(_, id)| id.as_ref().is_some_and(|i| p.contains(i))).map(|(ip, _)| *ip).collect();
            // Adverts can be stale (a cell moved) or missing (a node without a ce node daemon): no advertising peer
            // means ask every peer rather than none.
            if v.is_empty() { all() } else { v }
        }
        _ => all(),
    }
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/".into()))
}

/// The ce node's data dir, where ce-node and ce-iam keep identity/, iam/ and api.token: `$CE_DATA_DIR`, else
/// `~/Library/Application Support/ce` on macOS, else `$XDG_DATA_HOME/ce` or `~/.local/share/ce`.
pub fn ce_data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("CE_DATA_DIR") {
        return PathBuf::from(d);
    }
    if cfg!(target_os = "macos") {
        return home().join("Library/Application Support/ce");
    }
    match std::env::var("XDG_DATA_HOME") {
        Ok(x) if !x.is_empty() => PathBuf::from(x).join("ce"),
        _ => home().join(".local/share/ce"),
    }
}

/// The ceapp.toml whose `[wire] api` equals `api`, searched in `$CE_WIRE_APPS` or ~/dev (depth 3). An instance name
/// `<api>#<name>` matches the cell.toml with that `api` and `name = "<name>"`; a bare api prefers a cell.toml without
/// a `name`, else any instance of it.
pub fn find_manifest(api: &str) -> Option<PathBuf> {
    // A start after an idle stop is on a caller's path: the walk over ~/dev (868 cell.tomls on one host) is
    // done once per api, then the remembered file is read back and checked (one read). A moved or edited manifest
    // falls through to the walk. `CE_WIRE_MANIFEST_CACHE=0` walks every time.
    let root = apps_root().display().to_string();
    let cache = std::env::var("CE_WIRE_MANIFEST_CACHE").map_or(true, |v| v != "0");
    let key = (root, api.to_string());
    if cache {
        let hit = MANIFESTS.lock().unwrap().as_ref().and_then(|m| m.get(&key).cloned());
        if let Some(p) = hit {
            if std::fs::read_to_string(&p).is_ok_and(|t| manifest_is(&t, api)) {
                return Some(p);
            }
            if let Some(m) = MANIFESTS.lock().unwrap().as_mut() {
                m.remove(&key);
            }
        }
    }
    let found = find_manifest_walk(api);
    if let (true, Some(p)) = (cache, &found) {
        MANIFESTS.lock().unwrap().get_or_insert_with(Default::default).insert(key, p.clone());
    }
    found
}

type ManifestCache = Option<std::collections::HashMap<(String, String), PathBuf>>;
/// `find_manifest` hits: (`$CE_WIRE_APPS`, name) -> cell.toml.
static MANIFESTS: std::sync::Mutex<ManifestCache> = std::sync::Mutex::new(None);

/// Whether a remembered cell.toml still serves `api`: its api, and for an instance its name.
fn manifest_is(toml: &str, api: &str) -> bool {
    let name = wire_field(toml, "name").filter(|n| !n.is_empty());
    wire_field(toml, "api").as_deref() == Some(crate::base_api(api))
        && match crate::instance_of(api) {
            Some(i) => name.as_deref() == Some(i),
            None => true,
        }
}

fn find_manifest_walk(api: &str) -> Option<PathBuf> {
    let (base, inst) = (crate::base_api(api), crate::instance_of(api));
    let mut any = None;
    let hit = find_manifest_where(&mut |t| {
        if wire_field(t, "api").as_deref() != Some(base) {
            return false;
        }
        let name = wire_field(t, "name").filter(|n| !n.is_empty());
        match inst {
            Some(i) => name.as_deref() == Some(i),
            None if name.is_none() => true,
            None => {
                any.get_or_insert(());
                false
            }
        }
    });
    match (hit, any, inst) {
        (Some(m), _, _) => Some(m),
        (None, Some(()), None) => find_manifest_where(&mut |t| wire_field(t, "api").as_deref() == Some(base)),
        _ => None,
    }
}

/// Where cell.tomls are searched: `$CE_WIRE_APPS`, else ~/dev.
fn apps_root() -> PathBuf {
    std::env::var("CE_WIRE_APPS").map(PathBuf::from).unwrap_or_else(|_| home().join("dev"))
}

fn find_manifest_where(want: &mut dyn FnMut(&str) -> bool) -> Option<PathBuf> {
    let root = apps_root();
    let mut stack = vec![(root, 0)];
    while let Some((dir, depth)) = stack.pop() {
        for f in ["cell.toml", "ceapp.toml"] {
            let m = dir.join(f);
            if let Ok(t) = std::fs::read_to_string(&m) {
                if want(&t) {
                    return Some(m);
                }
            }
        }
        if depth < 3 {
            for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let n = e.file_name();
                let n = n.to_string_lossy();
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false) && !n.starts_with('.') && n != "target" && n != "node_modules" {
                    stack.push((e.path(), depth + 1));
                }
            }
        }
    }
    None
}

/// A `key = value` line inside the `[cell]` table (cell.toml) or `[wire]` table (ceapp.toml, the old name). Minimal on purpose: no TOML dependency in the core path.
fn wire_field(toml: &str, key: &str) -> Option<String> {
    let mut inside = false;
    for line in toml.lines().map(str::trim) {
        if line.starts_with('[') {
            inside = line == "[wire]" || line == "[cell]";
        } else if inside {
            if let Some((k, v)) = line.split_once('=') {
                if k.trim() == key {
                    return Some(v.split('#').next()?.trim().trim_matches('"').to_string());
                }
            }
        }
    }
    None
}

/// The owner of cell `api` here: `[cell] owner` of its cell.toml, without the `foreman/` prefix. What the door's
/// STOP-OWNER matches: one command over ce-net shuts an owner's cells down.
pub fn owner_of(api: &str) -> Option<String> {
    let t = std::fs::read_to_string(find_manifest(api)?).ok()?;
    wire_field(&t, "owner").map(|o| lane_name(&o).to_string()).filter(|o| !o.is_empty())
}

/// `foreman/team.2` and `team.2` name the same owner.
pub fn lane_name(s: &str) -> &str {
    s.trim().strip_prefix("foreman/").unwrap_or(s.trim())
}

/// How the door starts a cell, run in the manifest's folder:
/// - `[cell] crate = "<name>"` + `args = [...]`: the newer of `<cargo target>/release/<name>` and the installed
///   `~/.local/bin/<name>` (what systemd runs), so a cell already installed is never rebuilt (no start scripts:
///   start routines are cells too);
/// - `[cell] spawn = ["argv", ...]` (old ceapp.toml cells, until they are Rust).
fn spawn_cmd(toml: &str) -> Option<Vec<String>> {
    if let Some(c) = wire_field(toml, "crate") {
        let mut v = vec![cell_binary(&c).display().to_string()];
        v.extend(argv_field(toml, "args").unwrap_or_default());
        return Some(v);
    }
    argv_field(toml, "spawn")
}

/// The binary for `crate = c`: the newer of the build output and `~/.local/bin/<c>`; the build output path when
/// neither exists (then [`unbuilt`] is true and the door builds it).
fn cell_binary(c: &str) -> PathBuf {
    let built = target_dir().join("release").join(c);
    let installed = home().join(".local/bin").join(c);
    let at = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    match (at(&built), at(&installed)) {
        (Some(b), Some(i)) if i > b => installed,
        (None, Some(_)) => installed,
        _ => built,
    }
}

/// `$CARGO_TARGET_DIR`, else the shared `~/.cache/ce-cargo-target` (one build cache for every cell on the machine).
pub fn target_dir() -> PathBuf {
    std::env::var("CARGO_TARGET_DIR").map(PathBuf::from).unwrap_or_else(|_| home().join(".cache/ce-cargo-target"))
}

/// Build a cell into `target_dir()` for `crate =` cells: through build.offload (`build-offload cargo build --release -p
/// <crate>`, the binary comes back to the same `<target>/release/<crate>`), so a door never compiles on its own node
/// (a door update once ran cargo on a serving node). Only a door
/// whose own env has `CE_LOCAL_BUILD=1` (a build node) runs `nice -n 19 cargo build --release -j2` itself. Else the
/// old `build` argv.
pub fn build(manifest: &Path) -> Result<(), String> {
    let t = std::fs::read_to_string(manifest).map_err(|e| e.to_string())?;
    let dir = manifest.parent().unwrap_or(Path::new("."));
    let local = std::env::var("CE_LOCAL_BUILD").is_ok_and(|v| v == "1");
    let offload = [home().join(".local/bin/build-offload"), home().join(".cargo/bin/build-offload")].into_iter().find(|p| p.is_file());
    let argv = match wire_field(&t, "crate") {
        Some(c) => crate_build_argv(&c, local, offload.as_deref())?,
        None => match argv_field(&t, "build") {
            Some(b) => b,
            None => return Ok(()),
        },
    };
    let api = wire_field(&t, "api").unwrap_or_default();
    run_logged(&argv, dir, &api, "build", &[("CARGO_TARGET_DIR", target_dir()), ("CE_NO_LOCAL_BUILD", PathBuf::from(if local { "0" } else { "1" }))])
}

/// The argv that builds `crate = c`: local cargo only when `local` (`CE_LOCAL_BUILD=1` in the door's env), else the
/// build-offload client; neither is an error that says what to do, never a quiet local build.
pub fn crate_build_argv(c: &str, local: bool, offload: Option<&Path>) -> Result<Vec<String>, String> {
    if local {
        return Ok(["nice", "-n", "19", "cargo", "build", "--release", "-j2", "-p", c].map(String::from).to_vec());
    }
    let o = offload.ok_or(format!("{c}: no build-offload on this node; build it elsewhere and install, or set CE_LOCAL_BUILD=1 in this door's env"))?;
    Ok([o.display().to_string()].into_iter().chain(["cargo", "build", "--release", "-p", c].map(String::from)).collect())
}

/// The name a cell.toml registers and is found by: `api`, or `<api>#<name>` when it has `name = "<name>"`.
pub fn manifest_key(toml: &str) -> String {
    crate::instance_key(&wire_field(toml, "api").unwrap_or_default(), &wire_field(toml, "name").unwrap_or_default())
}

fn argv_field(toml: &str, key: &str) -> Option<Vec<String>> {
    let v = wire_field(toml, key)?;
    let v = v.trim().strip_prefix('[')?.strip_suffix(']')?;
    Some(v.split(',').map(|s| s.trim().trim_matches('"').to_string()).filter(|s| !s.is_empty()).collect())
}

/// `[cell] requires = ["tmux", ...]` (binaries on PATH) and `os = ["linux", "macos"]`: why this machine cannot run
/// the cell, or None. An unmet cell is refused with NoCell, so `by_name` goes to a peer instead of a broken local spawn.
pub fn unmet(manifest: &Path) -> Option<String> {
    let t = std::fs::read_to_string(manifest).ok()?;
    if let Some(os) = argv_field(&t, "os") {
        if !os.iter().any(|o| o == std::env::consts::OS) {
            return Some(format!("needs os {os:?}, this is {}", std::env::consts::OS));
        }
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    let missing: Vec<String> = argv_field(&t, "requires")
        .unwrap_or_default()
        .into_iter()
        .filter(|b| !std::env::split_paths(&path).any(|d| d.join(b).is_file()))
        .collect();
    (!missing.is_empty()).then(|| format!("requires {missing:?} on PATH"))
}

pub fn spawn(manifest: &Path) -> Result<(), WireError> {
    spawn_pid(manifest, None).map(|_| ())
}

/// ` rev=<sha>` for a REGISTER line: the git rev this process was built from, from `$CE_CELL_REV` (the door sets it
/// when it starts a build of a known rev; a cell's build.rs can bake it in and set it in main). Empty when unknown.
pub fn rev_field() -> String {
    std::env::var("CE_CELL_REV").ok().filter(|r| !r.is_empty() && !r.contains(char::is_whitespace)).map(|r| format!(" rev={r}")).unwrap_or_default()
}

/// This machine's environment for one cell: `KEY=VALUE` lines in `$CE_DOOR_ENV_DIR/<api>.env` (default
/// `~/.config/ce-door/env`); `#` lines and blanks skipped. A choice for one machine (e.g. one machine's state.store with
/// STATE_STORE_LEGACY=0) without restarting the door and every cell under it, and without putting it in
/// the repo's cell.toml, which every machine shares. Never put a secret here: secrets come from the keys cell.
pub fn cell_env(api: &str) -> Vec<(String, String)> {
    if api.is_empty() || api.contains(['/', '\\']) || api.starts_with('.') {
        return vec![];
    }
    let dir = std::env::var_os("CE_DOOR_ENV_DIR").map(PathBuf::from).unwrap_or_else(|| home().join(".config/ce-door/env"));
    std::fs::read_to_string(dir.join(format!("{api}.env")))
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .filter(|(k, _)| !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .collect()
}

/// [`spawn`], returning the new process id (the door's drift update waits for that pid to register). `rev`: set as
/// `$CE_CELL_REV` in the process, so it registers with the rev it was built from.
pub fn spawn_pid(manifest: &Path, rev: Option<&str>) -> Result<u32, WireError> {
    if let Some(why) = unmet(manifest) {
        return Err(WireError::Io(format!("{}: {why}", manifest.display())));
    }
    let t = std::fs::read_to_string(manifest).map_err(|e| WireError::Io(e.to_string()))?;
    let argv = spawn_cmd(&t).ok_or_else(|| WireError::Io(format!("{}: no [cell] crate or spawn", manifest.display())))?;
    let dir = manifest.parent().unwrap_or(Path::new("."));
    emit("start", &wire_field(&t, "api").unwrap_or_default(), &argv.join(" "));
    let mut ch = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(dir)
        .envs(cell_env(&wire_field(&t, "api").unwrap_or_default()))
        .envs(rev.map(|r| ("CE_CELL_REV", r)))
        .stdin(std::process::Stdio::null())
        .spawn()
        .map_err(|e| {
            // said in the event log too: a start with no outcome read as a restart loop (seen: 8 autostart
            // cells whose binaries lost their exec bit showed 495 bare "start" lines, no "failed")
            emit("failed", &wire_field(&t, "api").unwrap_or_default(), &format!("spawn: {e}"));
            WireError::Io(format!("spawn {argv:?}: {e}"))
        })?;
    // Reap the cell when it exits: a dropped Child is never waited, and a door that respawns a dying cell piles up
    // zombies until fork fails (seen: 879 <defunct> under ce-door, "fork failed").
    let api = wire_field(&t, "api").unwrap_or_default();
    let pid = ch.id();
    std::thread::spawn(move || {
        let st = ch.wait().map(|s| s.to_string()).unwrap_or_else(|e| e.to_string());
        emit("exited", &api, &st);
    });
    Ok(pid)
}

/// The cell index: `<api> <git url> <dir>` per line, `$CE_CELLS_INDEX` or `~/dev/rust-stack/cells.index`.
/// A repo is how a cell reproduces: a machine without the cell clones its repo, builds, starts it.
pub fn cells_index() -> Vec<(String, String, String)> {
    let p = std::env::var("CE_CELLS_INDEX").map(PathBuf::from).unwrap_or_else(|_| home().join("dev/rust-stack/cells.index"));
    std::fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut w = crate::strip_comment(l).split_whitespace();
            Some((w.next()?.to_string(), w.next()?.to_string(), w.next()?.to_string()))
        })
        .collect()
}

/// What the door does, live (watch a cell being installed and reproduced in real time):
/// one line per event, `<unix ms> <kind> <api> <detail>`; kinds: register, unregister, reproduce, clone, build, start,
/// started, failed, stop. The last `EVENT_KEEP` lines are kept for late watchers.
pub const EVENT_KEEP: usize = 500;
type Watchers = (std::collections::VecDeque<String>, Vec<std::sync::mpsc::Sender<String>>);
static EVENTS: std::sync::Mutex<Watchers> = std::sync::Mutex::new((std::collections::VecDeque::new(), Vec::new()));

pub fn emit(kind: &str, api: &str, detail: &str) {
    let ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    let line = format!("{ms} {kind} {api} {}", detail.replace('\n', " "));
    let mut e = EVENTS.lock().unwrap();
    if e.0.len() >= EVENT_KEEP {
        e.0.pop_front();
    }
    e.0.push_back(line.clone());
    e.1.retain(|tx| tx.send(line.clone()).is_ok());
}

/// The kept events and a receiver for every new one.
pub fn watch() -> (Vec<String>, std::sync::mpsc::Receiver<String>) {
    let (tx, rx) = std::sync::mpsc::channel();
    let mut e = EVENTS.lock().unwrap();
    e.1.push(tx);
    (e.0.iter().cloned().collect(), rx)
}

/// Run `argv` in `cwd`, every output line (cargo and git write progress to stderr) emitted as `kind` for `api`.
fn run_logged(argv: &[String], cwd: &Path, api: &str, kind: &str, env: &[(&str, PathBuf)]) -> Result<(), String> {
    use std::io::BufRead;
    emit(kind, api, &argv.join(" "));
    let mut c = std::process::Command::new(&argv[0]);
    c.args(&argv[1..]).current_dir(cwd).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    for (k, v) in env {
        c.env(k, v);
    }
    let mut ch = c.spawn().map_err(|e| format!("{argv:?}: {e}"))?;
    let out = ch.stdout.take().unwrap();
    let (a, k) = (api.to_string(), kind.to_string());
    let t = std::thread::spawn(move || std::io::BufReader::new(out).lines().map_while(Result::ok).for_each(|l| emit(&k, &a, &l)));
    // git and cargo redraw progress with \r: split on it too, so each step is its own event.
    let mut err = std::io::BufReader::new(ch.stderr.take().unwrap());
    let mut buf = Vec::new();
    while err.read_until(b'\n', &mut buf).map(|n| n > 0).unwrap_or(false) {
        for part in String::from_utf8_lossy(&buf).split('\r').map(str::trim).filter(|p| !p.is_empty()) {
            eprintln!("ce-door: {kind} {api}: {part}");
            emit(kind, api, part);
        }
        buf.clear();
    }
    let _ = t.join();
    let st = ch.wait().map_err(|e| e.to_string())?;
    st.success().then_some(()).ok_or_else(|| format!("{argv:?}: {st}"))
}

static REPRODUCING: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Failed reproduces: (api, when, why). A cell that cannot be cloned or built here (a private repo without
/// credentials) is tried again only after `REPRODUCE_COOLDOWN`; before, every call retried it (seen: one cell
/// cloned 11,684 times in 6 h).
static FAILED: std::sync::Mutex<Vec<(String, std::time::Instant, String)>> = std::sync::Mutex::new(Vec::new());
const REPRODUCE_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(600);

/// The refusal for `api` while its last failure is younger than the cooldown, else None.
fn cooling(failed: &[(String, std::time::Instant, String)], api: &str, now: std::time::Instant) -> Option<String> {
    let (_, at, why) = failed.iter().find(|(a, _, _)| a == api)?;
    let age = now.saturating_duration_since(*at);
    (age < REPRODUCE_COOLDOWN).then(|| {
        format!("{api}: reproduce failed {}s ago ({why}); next try in {}s", age.as_secs(), (REPRODUCE_COOLDOWN - age).as_secs())
    })
}

/// Start reproducing cell `api` on this machine in the background: `git clone` its repo from the index into the
/// apps root (`$CE_WIRE_APPS` or ~/dev), run `[cell] build = [argv]` if set, then spawn it. Returns what it is doing,
/// for the caller's NoCell refusal ("retry"); a second call while it runs does nothing. Logs to stderr (the door's).
pub fn reproduce(api: &str) -> Result<String, String> {
    let Some((_, url, dir)) = cells_index().into_iter().find(|(a, _, _)| a == api) else {
        return Err(format!("{api}: no cell.toml here and not in the cell index"));
    };
    if let Some(why) = cooling(&FAILED.lock().unwrap(), api, std::time::Instant::now()) {
        return Err(why);
    }
    {
        let mut r = REPRODUCING.lock().unwrap();
        if r.iter().any(|a| a == api) {
            return Ok(format!("{api}: reproducing from {url}, retry"));
        }
        r.push(api.to_string());
    }
    let root = std::env::var("CE_WIRE_APPS").map(PathBuf::from).unwrap_or_else(|_| home().join("dev"));
    let (api2, url2) = (api.to_string(), url.clone());
    emit("reproduce", api, &url);
    std::thread::spawn(move || {
        let target = root.join(&dir);
        let run = |argv: &[String], cwd: &Path| run_logged(argv, cwd, &api2, "clone", &[]);
        let r = (|| {
            if !target.exists() {
                run(&["git".into(), "clone".into(), "--progress".into(), "--depth".into(), "1".into(), url2.clone(), target.display().to_string()], &root)?;
            }
            let m = find_manifest(&api2).ok_or_else(|| format!("cloned {url2} but no cell.toml with api {api2}"))?;
            if let Some(why) = unmet(&m) {
                return Err(format!("{api2}: not runnable here, {why}"));
            }
            build(&m)?;
            for n in needs(&m) {
                // Not knowing the door's registry here, a need found by cell.toml is started only if absent from
                // the index walk; the door's own spawn-on-call covers the rest.
                if find_manifest(&n).is_none() {
                    let _ = reproduce(&n);
                }
            }
            spawn(&m).map_err(|e| e.to_string())
        })();
        eprintln!("ce-door: reproduce {api2} from {url2}: {}", match &r { Ok(()) => "started".to_string(), Err(e) => e.clone() });
        let mut f = FAILED.lock().unwrap();
        f.retain(|(a, _, _)| a != &api2);
        if let Err(e) = &r {
            emit("failed", &api2, e);
            f.push((api2.clone(), std::time::Instant::now(), e.chars().take(200).collect()));
        }
        drop(f);
        REPRODUCING.lock().unwrap().retain(|a| a != &api2);
    });
    Ok(format!("{api}: reproducing from {url} (clone, build, start), retry"))
}

/// Update cell `api` in place: `git pull --ff-only` in its repo, build, then `swap()` (the door stops the running
/// processes) and spawn the new build. In the background; the old version answers until the new one is built.
/// Events: update, clone (git lines), build lines, stop, start, register; failed on any error (the old one keeps running).
pub fn update(api: &str, swap: Box<dyn FnOnce() + Send>) -> Result<String, String> {
    let m = find_manifest(api).ok_or_else(|| format!("{api}: no cell.toml here"))?;
    {
        let mut r = REPRODUCING.lock().unwrap();
        if r.iter().any(|a| a == api) {
            return Ok(format!("{api}: already building"));
        }
        r.push(api.to_string());
    }
    let dir = m.parent().map(Path::to_path_buf).unwrap_or_default();
    emit("update", api, &dir.display().to_string());
    let api2 = api.to_string();
    std::thread::spawn(move || {
        let r = run_logged(&["git".into(), "pull".into(), "--ff-only".into(), "--progress".into()], &dir, &api2, "clone", &[])
            .and_then(|()| build(&m))
            .and_then(|()| {
                swap();
                // A supervisor-owned cell (`[launch] by = "systemd"`) comes back by itself on the new binary; spawning
                // here too made a second copy (2026-10-15 node.online: door pid + systemd pid). Others take the spawn
                // claim so a by-name Hello in the same second attaches instead of starting another.
                if launched_by(&m).is_some() {
                    return Ok(());
                }
                if !claim_spawn(&api2, SPAWN_WINDOW) {
                    return Ok(());
                }
                spawn(&m).map_err(|e| format!("{e:?}"))
            });
        eprintln!("ce-door: update {api2}: {}", match &r { Ok(()) => "started".to_string(), Err(e) => e.clone() });
        let mut f = FAILED.lock().unwrap();
        f.retain(|(a, _, _)| a != &api2);
        if let Err(e) = &r {
            emit("failed", &api2, e);
            f.push((api2.clone(), std::time::Instant::now(), e.chars().take(200).collect()));
        }
        drop(f);
        REPRODUCING.lock().unwrap().retain(|a| a != &api2);
    });
    Ok(format!("{api}: updating (git pull, build, restart)"))
}

/// The cells this cell calls: `[cell] depends_on = ["api@major", ...]` (the contract)
/// and the older `needs = ["api", ...]`. The door starts them before it, so a
/// cell's dependencies are spawned automatically.
pub fn needs(manifest: &Path) -> Vec<String> {
    let t = std::fs::read_to_string(manifest).unwrap_or_default();
    let mut v = argv_field(&t, "needs").unwrap_or_default();
    for d in argv_field(&t, "depends_on").unwrap_or_default() {
        let api = d.split('@').next().unwrap_or_default().to_string();
        if !api.is_empty() && !v.contains(&api) {
            v.push(api);
        }
    }
    v
}

/// Make sure cell `api` runs on this machine: nothing if `running(api)`, else start its needs (depth first, each
/// once), then spawn it from its cell.toml, or reproduce it from the cell index. Returns what it did.
pub fn ensure(api: &str, running: &dyn Fn(&str) -> bool) -> Result<String, String> {
    ensure_in(api, running, SPAWN_WINDOW)
}

/// How long a spawn of one api counts as in flight: a second `ensure` of that api within it (autostart racing a
/// by-name Hello) attaches to the first instead of starting a second process. A cell that never registers is
/// retried after the window.
pub const SPAWN_WINDOW: Duration = Duration::from_secs(30);
static SPAWNING: std::sync::Mutex<Vec<(String, std::time::Instant)>> = std::sync::Mutex::new(Vec::new());

/// Forget the spawn of `api` in flight: only the door's restart calls it (no replica is left, so the old spawn is
/// over). Clearing it on register instead made autostart start a second copy: a dependent's autostart resolves needs
/// from a snapshot taken before the first copy registered (2026-10-15 door swap: twin.world, message.deliver x2).
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn spawned(api: &str) {
    SPAWNING.lock().unwrap().retain(|(a, _)| a != api);
}

/// True when the caller owns the spawn of `api`; false when one is already in flight within `window`.
fn claim_spawn(api: &str, window: Duration) -> bool {
    let mut v = SPAWNING.lock().unwrap();
    let now = std::time::Instant::now();
    v.retain(|(_, t)| now.duration_since(*t) < window);
    if v.iter().any(|(a, _)| a == api) {
        return false;
    }
    v.push((api.to_string(), now));
    true
}

/// How long `ensure` waits for a need that has no cell.toml here and is not in the cell index to register by itself
/// (a cell systemd starts, e.g. state.store) before refusing. Without it the door's first autostart pass
/// after a restart failed net.name-resolve on its `depends_on = ["state.store@2"]`, a second before state.store
/// registered, and the cell came up only on the next pass 60 s later (before this wait).
pub static NEED_WAIT_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(5000);

pub fn ensure_in(api: &str, running: &dyn Fn(&str) -> bool, window: Duration) -> Result<String, String> {
    fn go(api: &str, running: &dyn Fn(&str) -> bool, window: Duration, seen: &mut Vec<String>, did: &mut Vec<String>) -> Result<(), String> {
        if running(api) {
            SPAWNING.lock().unwrap().retain(|(a, _)| a != api);
        }
        if seen.iter().any(|a| a == api) || running(api) {
            return Ok(());
        }
        let top = seen.is_empty();
        seen.push(api.to_string());
        match find_manifest(api) {
            Some(m) => {
                if let Some(why) = unmet(&m) {
                    return Err(format!("{api}: not runnable here, {why}"));
                }
                if let Some(by) = launched_by(&m) {
                    if let Some(unit) = std::fs::read_to_string(&m).ok().as_deref().and_then(supervisor_unit) {
                        did.push(systemctl("start", &unit).map_err(|e| format!("{api}: {e}"))?);
                        return Ok(());
                    }
                    return Err(format!("{api}: not running; started by {by}, not the door"));
                }
                for n in needs(&m) {
                    go(&n, running, window, seen, did)?;
                }
                if !claim_spawn(api, window) {
                    did.push(format!("{api}: starting (attached to the spawn in flight)"));
                    return Ok(());
                }
                if unbuilt(&m) {
                    did.push(build_then_spawn(api, m));
                } else {
                    spawn(&m).map_err(|e| format!("{api}: {e:?}"))?;
                    did.push(format!("started {api}"));
                }
            }
            None if !top && !cells_index().iter().any(|(a, _, _)| a == api) => {
                let until = std::time::Instant::now() + Duration::from_millis(NEED_WAIT_MS.load(std::sync::atomic::Ordering::Relaxed));
                while !running(api) {
                    if std::time::Instant::now() >= until {
                        return Err(format!("{api}: no cell.toml here and not in the cell index, and it did not register"));
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                did.push(format!("{api}: registered by its own supervisor"));
            }
            None => did.push(reproduce(api)?),
        }
        Ok(())
    }
    let (mut seen, mut did) = (vec![], vec![]);
    go(api, running, window, &mut seen, &mut did)?;
    Ok(if did.is_empty() { format!("{api}: running") } else { did.join("; ") })
}

/// `[launch] by = "systemd"` (or any other supervisor): the door never spawns or restarts the cell, so a call made
/// while systemd is restarting it does not start a second copy (seen as duplicate copies before).
pub fn launched_by(manifest: &Path) -> Option<String> {
    let t = std::fs::read_to_string(manifest).ok()?;
    launch_field(&t, "by").filter(|v| v != "door")
}

/// One `key = value` under `[launch]` (quotes and a trailing comment dropped; empty = absent).
fn launch_field(toml: &str, key: &str) -> Option<String> {
    let mut in_launch = false;
    for l in toml.lines().map(str::trim) {
        if l.starts_with('[') {
            in_launch = l == "[launch]";
        } else if in_launch {
            if let Some((k, v)) = l.split_once('=') {
                if k.trim() == key {
                    return Some(v.split('#').next().unwrap_or("").trim().trim_matches('"').to_string()).filter(|v| !v.is_empty());
                }
            }
        }
    }
    None
}

/// The systemd user unit a `by = "systemd"` cell names (`[launch] unit = "search-hybrid-serve.service"`): the door's
/// PLACE / STOP / RESTART then run `systemctl --user start|stop|restart <unit>`, so a cell too big for the door's
/// cgroup is still started, stopped and restarted through ce. Without a unit
/// the door only reports it, as before. Only plain unit names: no options, no paths.
pub fn supervisor_unit(toml: &str) -> Option<String> {
    if launch_field(toml, "by").as_deref() != Some("systemd") {
        return None;
    }
    launch_field(toml, "unit").filter(|u| {
        !u.starts_with('-') && u.ends_with(".service") && u.chars().all(|c| c.is_ascii_alphanumeric() || "@._-".contains(c))
    })
}

/// `systemctl --user <verb> <unit>` for [`supervisor_unit`]; Err carries what systemctl said.
pub fn systemctl(verb: &str, unit: &str) -> Result<String, String> {
    let o = std::process::Command::new("timeout")
        .args(["90", "systemctl", "--user", verb, unit])
        .output()
        .map_err(|e| format!("systemctl {verb} {unit}: {e}"))?;
    if o.status.success() {
        Ok(format!("systemctl --user {verb} {unit}"))
    } else {
        Err(format!("systemctl --user {verb} {unit}: {}", String::from_utf8_lossy(&o.stderr).trim()))
    }
}

/// The unit of `api`'s cell.toml, when it names one.
pub fn unit_of(api: &str) -> Option<String> {
    supervisor_unit(&std::fs::read_to_string(find_manifest(api)?).ok()?)
}

/// The cell kinds the door stops when idle (`CE_DOOR_IDLE_S`) unless the cell.toml says otherwise: a `function`
/// answers calls and does nothing between them. Every other kind (ui-state, web, native, daemon, none) may hold work
/// no caller asks for, so it stays up.
pub const IDLE_STOP_KINDS: &[&str] = &["function"];

/// Whether the door may stop this cell (cell.toml text) once nobody has used it for `CE_DOOR_IDLE_S`: Ok, or the
/// reason it stays up. `[cell] keep = true` or `idle_stop = false` keep it; `idle_stop = true` lets any kind stop;
/// otherwise only [`IDLE_STOP_KINDS`]. A cell that works on a timer with no callers (a feed, a watcher) must say
/// `keep = true` or be in the door's autostart file.
pub fn idle_stoppable(toml: &str) -> Result<(), String> {
    if wire_field(toml, "keep").as_deref() == Some("true") {
        return Err("keep = true".into());
    }
    match wire_field(toml, "idle_stop").as_deref() {
        Some("false") => return Err("idle_stop = false".into()),
        Some("true") => return Ok(()),
        _ => {}
    }
    match wire_field(toml, "kind") {
        Some(k) if IDLE_STOP_KINDS.contains(&k.as_str()) => Ok(()),
        Some(k) => Err(format!("kind {k}: only {} cells stop when idle", IDLE_STOP_KINDS.join(", "))),
        None => Err("no [cell] kind: only function cells stop when idle".into()),
    }
}

/// `[launch] restart_backoff_ms = [first, max]`: a cell that exits by itself is restarted after `first` ms, doubling
/// per crash up to `max`. None: the cell is started on the next call only.
pub fn restart_backoff(manifest: &Path) -> Option<(u64, u64)> {
    let t = std::fs::read_to_string(manifest).ok()?;
    let l = t.lines().map(str::trim).find(|l| l.starts_with("restart_backoff_ms"))?;
    let v: Vec<u64> = l.split_once('=')?.1.split(|c: char| !c.is_ascii_digit()).filter(|x| !x.is_empty()).filter_map(|x| x.parse().ok()).collect();
    match v[..] {
        [a, b, ..] if a > 0 && b >= a => Some((a, b)),
        [a] if a > 0 => Some((a, a)),
        _ => None,
    }
}

/// The wait before restart number `n` (0 = first): `first * 2^n`, at most `max`.
pub fn restart_wait(first: u64, max: u64, n: u32) -> u64 {
    first.saturating_mul(1u64 << n.min(30)).min(max)
}

/// A `crate =` cell whose binary is not in the target dir yet.
pub(crate) fn unbuilt(manifest: &Path) -> bool {
    std::fs::read_to_string(manifest).ok().and_then(|t| spawn_cmd(&t).filter(|_| wire_field(&t, "crate").is_some())).is_some_and(|a| !Path::new(&a[0]).exists())
}

/// Build in the background (minutes for a first cargo build), then spawn. The door never blocks on a build; callers
/// get "building ..., retry" until the cell registers.
fn build_then_spawn(api: &str, m: PathBuf) -> String {
    if let Some(why) = cooling(&FAILED.lock().unwrap(), api, std::time::Instant::now()) {
        return why;
    }
    {
        let mut r = REPRODUCING.lock().unwrap();
        if r.iter().any(|a| a == api) {
            return format!("{api}: building, retry");
        }
        r.push(api.to_string());
    }
    let api2 = api.to_string();
    std::thread::spawn(move || {
        let r = build(&m).and_then(|()| spawn(&m).map_err(|e| format!("{e:?}")));
        eprintln!("ce-door: build {api2}: {}", match &r { Ok(()) => "started".to_string(), Err(e) => e.clone() });
        let mut f = FAILED.lock().unwrap();
        f.retain(|(a, _, _)| a != &api2);
        if let Err(e) = &r {
            emit("failed", &api2, e);
            f.push((api2.clone(), std::time::Instant::now(), e.chars().take(200).collect()));
        }
        drop(f);
        REPRODUCING.lock().unwrap().retain(|a| a != &api2);
    });
    format!("{api}: building (cargo build --release), retry")
}

/// The door's TCP port on every machine (D12a). `$CE_DOOR_PORT` overrides it, for tests.
pub const DOOR_PORT: u16 = 7700;

pub fn door_port() -> u16 {
    std::env::var("CE_DOOR_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(DOOR_PORT)
}

#[cfg(feature = "client")]
/// Makes the proof for one dial (`by_name_inner` calls it per door, replica and peer).
type Mint = std::sync::Arc<dyn Fn() -> Vec<u8> + Send + Sync>;

#[cfg(feature = "client")]
/// A caller-supplied token reused for every dial (the old `by_name(token)` behaviour).
fn reuse(token: Vec<u8>) -> Mint {
    std::sync::Arc::new(move || token.clone())
}

/// The error to report for the last step. A reused token is spent by the first door that checked its hello, so the
/// spawn step is refused "replayed hello" and that hid the real cause (the first door's timeout). Report the first
/// door's error then (it is also in `tried`); every other error stands.
#[cfg(feature = "client")]
fn last_cause(e: WireError, tried: &[String]) -> WireError {
    if !format!("{e:?}").contains("replayed hello") {
        return e;
    }
    match tried.iter().find(|t| t.starts_with("door ")) {
        Some(t) if t.contains("Timeout") => WireError::Timeout,
        Some(t) => WireError::Io(format!("{t} (then this door refused the reused token as a replay)")),
        None => e,
    }
}

#[cfg(feature = "client")]
impl<A: Api> crate::Client<A> {
    /// Connect to cell `A` wherever it runs, starting it if nothing runs it (`find.rs` has the order): this machine's
    /// door, then net.find's healthy replicas with `A`'s schema (failover in order), then the mesh peers' doors at once,
    /// then this machine's door with spawn (waits up to `SPAWN_WAIT`). While net.find knows a replica but none answers,
    /// the first three steps repeat with backoff for up to `find::RETRY_FOR` (a link blip) before the spawn.
    /// All failed: [`WireError::Unreachable`].
    pub async fn by_name(token: Vec<u8>) -> Result<Self, WireError> {
        Self::by_name_inner(reuse(token), None, A::NAME).await
    }

    /// [`Client::by_name`] with a fresh proof for every dial: `mint` is called once per door, replica and peer it
    /// tries. Use this when you can mint (`|| ce_gate::self_proof::<A>()`): one reused token is spent by the first door
    /// that checked its hello, even when the dial then timed out on our side, and the later steps were refused
    /// "replayed hello"; a proof minted before a slow net.find also arrived stale.
    pub async fn by_name_minted(mint: impl Fn() -> Vec<u8> + Send + Sync + 'static) -> Result<Self, WireError> {
        Self::by_name_inner(std::sync::Arc::new(mint), None, A::NAME).await
    }

    /// [`Client::by_name`] for instance `name` of the api (`obs.source#wx.metar`, `ce_wire::instance_key`): the same
    /// four steps, each asking for that instance; a door hands the connection to that instance only. If no machine
    /// answers for it, the last step (this machine's door with spawn) starts it from its cell.toml here, or, when
    /// this machine has none, goes to any process of the bare api. `token` must be signed for the instance name
    /// (`ce_gate::proof_as` / `self_proof_as`).
    pub async fn by_instance(name: &str, token: Vec<u8>) -> Result<Self, WireError> {
        let key = crate::instance_key(A::NAME, name);
        if !crate::valid_key(&key) {
            return Err(WireError::Io(format!("{key}: not a valid instance name")));
        }
        Self::by_name_inner(reuse(token), None, &key).await
    }

    /// [`Client::by_instance`] with a fresh proof per dial (see [`Client::by_name_minted`]); `mint` signs for the
    /// instance name.
    pub async fn by_instance_minted(name: &str, mint: impl Fn() -> Vec<u8> + Send + Sync + 'static) -> Result<Self, WireError> {
        let key = crate::instance_key(A::NAME, name);
        if !crate::valid_key(&key) {
            return Err(WireError::Io(format!("{key}: not a valid instance name")));
        }
        Self::by_name_inner(std::sync::Arc::new(mint), None, &key).await
    }

    /// [`Client::by_name`], and a replica at an older version this client holds adapters for is called through them
    /// ([`Client::connect_older`]): a cell's new client keeps working while some machines still run its old server.
    /// The local spawn, last, starts this machine's own build.
    pub async fn by_name_older(token: Vec<u8>, olders: crate::adapt::OlderServers) -> Result<Self, WireError> {
        Self::by_name_inner(reuse(token), Some(olders), A::NAME).await
    }

    async fn dial(addr: String, hello_api: &str, token: Vec<u8>, wait: std::time::Duration, olders: Option<&crate::adapt::OlderServers>) -> Result<Self, WireError> {
        match olders {
            Some(o) => Self::connect_older_opts(addr, token, o, wait).await,
            None => Self::connect_opts_as(addr, hello_api, token, false, wait).await,
        }
    }

    async fn by_name_inner(mint: Mint, olders: Option<crate::adapt::OlderServers>, hello_api: &str) -> Result<Self, WireError> {
        let older_schemas = olders.as_ref().map(|o| o.schemas()).unwrap_or_default();
        let port = door_port();
        let local = SocketAddr::from(([127, 0, 0, 1], port));
        let mut tried = Vec::new();
        let mut find_err = None;
        // net.find knew a replica of this schema: worth retrying through a link blip before spawning here.
        let mut known = false;
        let start = std::time::Instant::now();
        let away = crate::find::pinned_away(hello_api);
        let rd = if away.is_some() { crate::find::REMOTE_DEADLINE } else { crate::DEADLINE };
        for round in 0.. {
            match Self::dial(local.to_string(), hello_api, mint(), crate::DEADLINE, olders.as_ref()).await {
                Ok(c) => return Ok(c),
                Err(e) => tried.push(format!("door {local}: {e:?}")),
            }
            match crate::find::find_async(hello_api, crate::find::major::<A>()).await {
                Some(Ok(reply)) => {
                    for a in crate::find::usable_with::<A>(&reply, &older_schemas) {
                        match Self::dial(a.clone(), hello_api, mint(), rd, olders.as_ref()).await {
                            Ok(c) => return Ok(c),
                            Err(e) => tried.push(format!("replica {a}: {e:?}")),
                        }
                    }
                    known |= !crate::find::usable_with::<A>(&reply, &older_schemas).is_empty();
                    if reply.replicas.is_empty() {
                        tried.push("net.find: no replica".into());
                    }
                }
                Some(Err(e)) => {
                    tried.push(format!("net.find: {e:?}"));
                    find_err = Some(e);
                }
                None => tried.push("net.find: no finder answered".into()),
            }
            let mut set = tokio::task::JoinSet::new();
            for ip in candidates(hello_api) {
                let t = mint();
                let o = olders.clone();
                let h = hello_api.to_string();
                set.spawn(async move { Self::dial(SocketAddr::new(ip, port).to_string(), &h, t, rd, o.as_ref()).await });
            }
            while let Some(r) = set.join_next().await {
                match r {
                    Ok(Ok(c)) => return Ok(c),
                    Ok(Err(e)) => tried.push(format!("peer: {e:?}")),
                    Err(_) => {}
                }
            }
            let next = if away.is_some() { crate::find::remote_wait(start) } else { crate::find::retry_wait(start, round).filter(|_| known) };
            match next {
                Some(w) => tokio::time::sleep(w).await,
                None => break,
            }
        }
        if let Some(why) = away {
            tried.push(format!("not runnable here ({why}), so no local spawn: the remote replica did not answer for {}s", crate::find::REMOTE_RETRY_FOR.as_secs()));
            return Err(crate::find::unreachable::<A>(find_err, tried, WireError::Timeout));
        }
        Self::connect_opts_as(local, hello_api, mint(), true, SPAWN_WAIT + crate::DEADLINE)
            .await
            .map_err(|e| crate::find::unreachable::<A>(find_err, tried.clone(), last_cause(e, &tried)))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_systemd_cell_names_its_unit() {
        let t = "[cell]\napi = \"search.hybrid\"\n[launch]\nby = \"systemd\"\nunit = \"search-hybrid-serve.service\" # big\n";
        assert_eq!(super::supervisor_unit(t).as_deref(), Some("search-hybrid-serve.service"));
        assert_eq!(super::supervisor_unit("[launch]\nby = \"systemd\"\n"), None, "no unit: report only");
        assert_eq!(super::supervisor_unit("[launch]\nby = \"door\"\nunit = \"x.service\"\n"), None);
        assert_eq!(super::supervisor_unit("[launch]\nby = \"systemd\"\nunit = \"--all\"\n"), None);
        assert_eq!(super::supervisor_unit("[launch]\nby = \"systemd\"\nunit = \"a b.service\"\n"), None);
        assert_eq!(super::supervisor_unit("[cell]\nunit = \"x.service\"\n[launch]\nby = \"systemd\"\n"), None, "unit outside [launch]");
    }

    #[test]
    fn a_failed_reproduce_waits_out_the_cooldown() {
        let t0 = std::time::Instant::now();
        let failed = vec![("x.y".to_string(), t0, "clone: no credentials".to_string())];
        let why = super::cooling(&failed, "x.y", t0 + std::time::Duration::from_secs(5)).unwrap();
        assert!(why.contains("failed 5s ago") && why.contains("next try in 595s"), "{why}");
        assert!(super::cooling(&failed, "x.y", t0 + super::REPRODUCE_COOLDOWN).is_none());
        assert!(super::cooling(&failed, "other.cell", t0).is_none());
    }


    // a door update never compiles on its own node unless that door's env says CE_LOCAL_BUILD=1
    #[test]
    fn door_builds_go_through_build_offload() {
        let o = Path::new("/h/.local/bin/build-offload");
        assert_eq!(crate_build_argv("apps-release", false, Some(o)).unwrap(), ["/h/.local/bin/build-offload", "cargo", "build", "--release", "-p", "apps-release"]);
        assert_eq!(crate_build_argv("x", true, Some(o)).unwrap()[..4], ["nice", "-n", "19", "cargo"]);
        assert!(crate_build_argv("x", false, None).unwrap_err().contains("CE_LOCAL_BUILD=1"));
    }

    #[test]
    fn owner_is_read_from_cell_toml_without_the_foreman_prefix() {
        let t = "[cell]\napi = \"x.y\"\nowner = \"foreman/team.2\"  # who runs it\n";
        assert_eq!(super::wire_field(t, "owner").as_deref().map(super::lane_name), Some("team.2"));
        assert_eq!(super::lane_name("team.2"), "team.2");
    }

    #[test]
    #[cfg(feature = "client")]
    fn a_replay_refusal_reports_the_first_door_error() {
        use super::{last_cause, WireError};
        let tried = vec!["door 127.0.0.1:7700: Timeout".to_string(), "net.find: NotFound".into()];
        let replay = WireError::Refused(crate::Refusal::Gate("replayed hello".into()));
        assert!(matches!(last_cause(replay, &tried), WireError::Timeout));
        let other = vec!["door 127.0.0.1:7700: Io(\"refused\")".to_string()];
        let replay = WireError::Refused(crate::Refusal::Gate("replayed hello".into()));
        assert!(matches!(last_cause(replay, &other), WireError::Io(m) if m.contains("refused") && m.contains("replay")));
        assert!(matches!(last_cause(WireError::Timeout, &other), WireError::Timeout));
        let replay = WireError::Refused(crate::Refusal::Gate("replayed hello".into()));
        assert!(matches!(last_cause(replay, &[]), WireError::Refused(_)));
    }

    #[test]
    fn a_cell_gets_this_machines_env_file_and_nothing_else() {
        let d = std::env::temp_dir().join(format!("ce-door-env-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("state.store.env"), "# this host: Python serves the legacy topic\nSTATE_STORE_LEGACY=0\n\nbad key=1\nA_B = x=y \n").unwrap();
        std::env::set_var("CE_DOOR_ENV_DIR", &d);
        assert_eq!(cell_env("state.store"), vec![("STATE_STORE_LEGACY".into(), "0".into()), ("A_B".into(), "x=y".into())]);
        assert!(cell_env("other.cell").is_empty());
        assert!(cell_env("../state.store").is_empty());
        std::env::remove_var("CE_DOOR_ENV_DIR");
        let _ = std::fs::remove_dir_all(&d);
    }
    use super::*;

    #[test]
    fn reads_wire_table() {
        let t = "[app]\nname = \"x\"\n[wire]\napi = \"servo.bus\" # typed\nport = 21000\nspawn = [\"target/release/x\", \"serve\"]\n";
        assert_eq!(wire_field(t, "api").as_deref(), Some("servo.bus"));
        assert_eq!(wire_field(t, "port").as_deref(), Some("21000"));
        assert_eq!(spawn_cmd(t).unwrap(), vec!["target/release/x", "serve"]);
        // a crate no host has installed: cell_binary prefers ~/.local/bin/<crate> when it exists, so a real cell name
        // ("docs-read", installed on some hosts) made this test depend on the machine
        let c = "[cell]\napi = \"t.wire-table\"\ncrate = \"ce-wire-test-not-installed\"\nargs = [\"serve\"]\n";
        assert_eq!(spawn_cmd(c).unwrap(), vec![target_dir().join("release/ce-wire-test-not-installed").display().to_string(), "serve".into()]);
    }

    #[test]
    fn reproduces_a_cell_from_its_repo() {
        let d = std::env::temp_dir().join(format!("ce-repro-{}", std::process::id()));
        let (src, apps) = (d.join("src"), d.join("apps"));
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&apps).unwrap();
        std::fs::write(src.join("cell.toml"), "[cell]\napi = \"t.repro\"\nbuild = [\"touch\", \"built\"]\nspawn = [\"true\"]\n").unwrap();
        let git = |args: &[&str], cwd: &Path| assert!(std::process::Command::new("git").args(args).current_dir(cwd).output().unwrap().status.success());
        git(&["init", "-q"], &src);
        git(&["add", "."], &src);
        git(&["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "c"], &src);
        std::fs::write(d.join("cells.index"), format!("t.repro file://{} repro # test\n", src.display())).unwrap();
        std::env::set_var("CE_CELLS_INDEX", d.join("cells.index"));
        std::env::set_var("CE_WIRE_APPS", &apps);
        assert!(reproduce("t.nope").is_err());
        assert!(reproduce("t.repro").unwrap().contains("reproducing"));
        for _ in 0..100 {
            if apps.join("repro/built").exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(apps.join("repro/built").exists(), "cloned and built");

        // needs: t.a needs t.b and t.c; t.c needs t.b. ensure starts b, c, a, each once; running cells are skipped.
        for (dir, toml) in [
            ("a", "[cell]\napi = \"t.a\"\nneeds = [\"t.b\", \"t.c\"]\nspawn = [\"touch\", \"a.on\"]\n"),
            ("b", "[cell]\napi = \"t.b\"\nspawn = [\"touch\", \"b.on\"]\n"),
            ("c", "[cell]\napi = \"t.c\"\ndepends_on = [\"t.b@1\"]\nspawn = [\"touch\", \"c.on\"]\n"),
        ] {
            std::fs::create_dir_all(apps.join(dir)).unwrap();
            std::fs::write(apps.join(dir).join("cell.toml"), toml).unwrap();
        }
        // requires / os: unmet = refused (so by_name asks a peer), met = runs.
        for (dir, toml) in [
            ("r1", "[cell]\napi = \"t.r1\"\nrequires = [\"no-such-binary-xyz\"]\nspawn = [\"touch\", \"r1.on\"]\n"),
            ("r2", "[cell]\napi = \"t.r2\"\nos = [\"plan9\"]\nspawn = [\"touch\", \"r2.on\"]\n"),
            ("r3", "[cell]\napi = \"t.r3\"\nrequires = [\"touch\"]\nos = [\"linux\", \"macos\"]\nspawn = [\"touch\", \"r3.on\"]\n"),
        ] {
            std::fs::create_dir_all(apps.join(dir)).unwrap();
            std::fs::write(apps.join(dir).join("cell.toml"), toml).unwrap();
        }
        assert!(ensure_in("t.r1", &|_| false, Duration::ZERO).unwrap_err().contains("no-such-binary-xyz"));
        assert!(ensure_in("t.r2", &|_| false, Duration::ZERO).unwrap_err().contains("plan9"));
        assert!(ensure_in("t.r3", &|_| false, Duration::ZERO).is_ok());

        assert_eq!(ensure_in("t.a", &|_| false, Duration::ZERO).unwrap(), "started t.b; started t.c; started t.a");
        assert_eq!(ensure_in("t.a", &|a| a == "t.b", Duration::ZERO).unwrap(), "started t.c; started t.a");
        assert_eq!(ensure_in("t.a", &|a| a == "t.a", Duration::ZERO).unwrap(), "t.a: running");
        std::thread::sleep(Duration::from_millis(200));
        assert!(["a", "b", "c"].iter().all(|d| apps.join(d).join(format!("{d}.on")).exists()));
        assert!(!apps.join("r1/r1.on").exists() && !apps.join("r2/r2.on").exists() && apps.join("r3/r3.on").exists());

        // A need with no cell.toml and no index row that its own supervisor registers a moment later: the dependent
        // starts once it does; one that never registers is refused after the wait.
        std::fs::create_dir_all(apps.join("dep")).unwrap();
        std::fs::write(apps.join("dep/cell.toml"), "[cell]\napi = \"t.dep\"\ndepends_on = [\"t.sysd@1\"]\nspawn = [\"touch\", \"dep.on\"]\n").unwrap();
        NEED_WAIT_MS.store(2000, std::sync::atomic::Ordering::Relaxed);
        let t0 = std::time::Instant::now();
        let later = move |a: &str| a == "t.sysd" && t0.elapsed() > Duration::from_millis(300);
        let r = ensure_in("t.dep", &later, Duration::ZERO).unwrap();
        assert_eq!(r, "t.sysd: registered by its own supervisor; started t.dep");
        assert!(t0.elapsed() >= Duration::from_millis(300) && t0.elapsed() < Duration::from_millis(2000), "{:?}", t0.elapsed());
        NEED_WAIT_MS.store(200, std::sync::atomic::Ordering::Relaxed);
        std::fs::write(apps.join("dep/cell.toml"), "[cell]\napi = \"t.dep2\"\ndepends_on = [\"t.never@1\"]\nspawn = [\"true\"]\n").unwrap();
        assert!(ensure_in("t.dep2", &|_| false, Duration::ZERO).unwrap_err().contains("did not register"));
        NEED_WAIT_MS.store(5000, std::sync::atomic::Ordering::Relaxed);

        // Two concurrent ensures of one api (autostart racing a by-name Hello) start one process.
        std::fs::create_dir_all(apps.join("race")).unwrap();
        std::fs::write(apps.join("race/cell.toml"), "[cell]\napi = \"t.race\"\nspawn = [\"sh\", \"-c\", \"echo x >> race.log\"]\n").unwrap();
        let hs: Vec<_> = (0..2).map(|_| std::thread::spawn(|| ensure("t.race", &|_| false).unwrap())).collect();
        let outs: Vec<String> = hs.into_iter().map(|h| h.join().unwrap()).collect();
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(std::fs::read_to_string(apps.join("race/race.log")).unwrap().lines().count(), 1, "{outs:?}");
        assert!(outs.iter().any(|o| o.contains("attached")), "{outs:?}");
    }
}
