//! ce-door: this machine's one ce-wire door (D12a), and the commands that place, stop and move cells.
//!
//! `ce-door [addr ...]`: run the door. Binds 127.0.0.1 and this machine's private overlay addresses on `door_port()`:
//!   every underlay network `$CE_NET` enables (ce-scale/netmesh, tailscale, netbird, zerotier; `ce_wire::underlay`), never 0.0.0.0 or a public address. Args override, and are held to the same rule.
//!   A Hello for a cell that is not running starts it (and its `[cell] needs`) only with a ce-cap granting
//!   `<api>:spawn` rooted at this node or a mesh peer (`ce_gate::spawn_gate`).
//! `ce-door id`                    this node's ce id (hex), for another machine's `~/.config/ce-wire/roots`
//! `ce-door list`                  cells running here
//! `ce-door idle`                  per cell: seconds unused and whether the door stops it when idle ($CE_DOOR_IDLE_S,
//!   default 900, 0 = off; a stopped cell starts again on its next call), then the cells stopped for idleness
//! `ce-door watch`                 the door's events live: register, clone, build lines, start, stop
//! `ce-door place <api> [mesh ip]` start the cell (and its needs) here, or on that machine's door
//! `ce-door stop <api>`            stop every process of the cell here
//! `ce-door stop-owner <owner> <why>` stop every cell here whose cell.toml `[cell] owner` is that owner; the reason is logged
//! autostart: `~/.config/ce-wire/autostart` lists the cells this machine always runs (placed at start, every 60 s)
//! `ce-door restart <api>`         planned restart (a deploy put a new binary in place): stop, wait, start; never a crash report
//! `ce-door update <api>`          git pull its repo, build, then swap the running processes for the new build
//! `ce-door move <api> <mesh ip>`  place it there, then stop it here
//! `ce-door bundle <identity>`     macOS: write this binary into ~/Applications/ce.app (id com.ce-net.ce) signed with
//!   that codesign identity. launchd runs the door from there; every cell it starts is its child, and macOS charges a
//!   child's Screen Recording / Accessibility to ce.app, so one grant covers every cell.
//!   A real certificate keeps the grant across rebuilds; "-" (ad hoc)
//!   does not.
use ce_wire::{door_port, door_sock, frame, Hello, Kind, Refusal, HEADER};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};

pub fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let r = match a.as_slice() {
        ["list"] => ctl("LIST"),
        ["idle"] => ctl("IDLE"),
        ["watch"] => ctl_stream("WATCH"),
        ["id"] => ce_gate::node_identity().map(|i| i.node_id().iter().map(|b| format!("{b:02x}")).collect()).map_err(|e| e.to_string()),
        ["place", api] => ctl(&format!("PLACE {api}")),
        ["place", api, ip] => place_remote(api, ip),
        ["stop", api] => ctl(&format!("STOP {api}")),
        ["stop-owner", owner, why @ ..] if !why.is_empty() => ctl(&format!("STOP-OWNER {owner} {}", why.join(" "))),
        ["update", api] => ctl(&format!("UPDATE {api}")),
        ["restart", api] => ctl(&format!("RESTART {api}")),
        ["move", api, ip] => place_remote(api, ip).and_then(|m| Ok(format!("{m}\n{}", ctl(&format!("STOP {api}"))?))),
        ["bundle", identity] => bundle(identity),
        [] | ["serve"] => return serve(),
        _ if a.iter().all(|x| x.parse::<SocketAddr>().is_ok()) => return serve(),
        _ => Err("usage: ce-door [serve | <bind addr>...] | id | list | idle | watch | place <api> [ip] | stop <api> | stop-owner <owner> <why> | move <api> <ip> | update <api> | restart <api> | bundle <identity>\n(an unknown argument used to start a second door and take over the socket)".into()),
    };
    match r {
        Ok(s) => println!("{s}"),
        Err(e) => {
            eprintln!("ce-door: {e}");
            std::process::exit(1);
        }
    }
}

fn serve() {
    #[cfg(target_os = "macos")]
    sign_self();
    // provider proof for the door's own calls out (CE_PROVIDER_PROOF=report|strict); the cells
    // it starts inherit the variable and turn it on themselves with `ce_gate::provider::enable_from_env`
    match ce_gate::provider::enable_from_env() {
        Ok(true) => eprintln!("ce-door: provider proof on ({})", std::env::var("CE_PROVIDER_PROOF").unwrap_or_default()),
        Ok(false) => {}
        Err(e) => eprintln!("ce-door: provider proof not on: {e}"),
    }
    let port = door_port();
    let binds: Vec<SocketAddr> = std::env::args().skip(1).filter_map(|a| a.parse().ok()).collect(); // "serve" parses as none
    if let Some(bad) = binds.iter().find(|b| !bindable(b.ip())) {
        eprintln!("ce-door: refusing to listen on {bad}: only loopback and private overlay addresses (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7)");
        std::process::exit(2);
    }
    let me = ce_gate::node_identity().expect("ce node identity");
    eprintln!("ce-door: cells register on {}, spawn gated by ce-cap <api>:spawn", door_sock().display());
    std::thread::spawn(keep_running);
    #[cfg(target_os = "macos")]
    std::thread::spawn(firewall_self);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio");
    let gate = Some(ce_gate::spawn_gate(me.node_id()));
    let run = if binds.is_empty() {
        rt.block_on(ce_wire::run_door_underlay(port, door_sock(), gate))
    } else {
        eprintln!("ce-door: listening {binds:?}");
        rt.block_on(ce_wire::run_door_gated(binds, door_sock(), gate))
    };
    if let Err(e) = run {
        eprintln!("ce-door: {e}");
        std::process::exit(1);
    }
}

/// The cells this machine always runs: `~/.config/ce-wire/autostart` (or `$CE_DOOR_AUTOSTART`), one api per line. The
/// door places each 2 s after it starts (boot, via launchd/systemd) and again every 60 s, so a crashed one comes back;
/// PLACE of a running cell does nothing.
///
/// Autostart only names cells a human listed. A long-lived worker placed by hand (not in autostart) is dropped by a
/// door restart and stays down until something calls it — that bit us on 2026-10-18 (sensor.flights, feed.inbound and
/// others fell when the door was restarted for the instance-names rollout). So the door also keeps a self-written
/// snapshot: each cycle it records cells that have been up for >= `RESTORE_MIN_CYCLES` cycles (~5 min = long-lived,
/// not a transient on-demand spawn) to `~/.config/ce-wire/running.snapshot` (or `$CE_DOOR_RUNNING`), and on start it
/// re-places, after a 45 s grace for supervised cells to come back on their own, every snapshot entry that is not in autostart and not already running. Transient cells never reach the
/// threshold, so they are not re-warmed. The snapshot is only overwritten when LIST succeeds, so a load-starved LIST
/// does not wipe the restore set.
fn keep_running() {
    use std::collections::{HashMap, HashSet};
    let home = std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default());
    let file = std::env::var("CE_DOOR_AUTOSTART").map(std::path::PathBuf::from).unwrap_or_else(|_| home.join(".config/ce-wire/autostart"));
    let snap = std::env::var("CE_DOOR_RUNNING").map(std::path::PathBuf::from).unwrap_or_else(|_| home.join(".config/ce-wire/running.snapshot"));
    const RESTORE_MIN_CYCLES: u32 = 5;
    const RESTORE_GRACE: std::time::Duration = std::time::Duration::from_secs(45);
    let autostart_set = || -> HashSet<String> {
        std::fs::read_to_string(&file).unwrap_or_default().lines()
            .map(ce_wire::strip_comment).map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect()
    };
    // `ce-door list` / ctl("LIST") answers one `<api> <count>` line per running cell; take the api.
    let running_now = || -> HashSet<String> {
        ctl("LIST").unwrap_or_default().lines().filter_map(|l| l.split_whitespace().next()).map(str::to_string).collect()
    };
    std::thread::sleep(std::time::Duration::from_secs(2));
    // Autostart first; the restore waits RESTORE_GRACE so a cell that a supervisor (systemd Restart=, launchd) brings
    // back registers its own copy first. Restoring at once raced them: the door's copies of
    // several cells won, and the systemd copies were refused every 10 s.
    for api in autostart_set() {
        let _ = ctl(&format!("PLACE {api}"));
    }
    std::thread::sleep(RESTORE_GRACE);
    // Restore long-lived cells a restart dropped, once, from the last snapshot. The restored set counts as long-lived
    // from cycle one: the counts restart at 0 with the door, and without this the first 4 cycles wrote an empty
    // snapshot over the good one (0 bytes right after a door swap).
    let mut seen: HashMap<String, u32> = HashMap::new();
    {
        let (a, up) = (autostart_set(), running_now());
        for api in std::fs::read_to_string(&snap).unwrap_or_default().lines().map(str::trim).filter(|l| !l.is_empty()) {
            seen.insert(api.to_string(), RESTORE_MIN_CYCLES - 1);
            if a.contains(api) || up.contains(api) {
                continue;
            }
            match ctl(&format!("PLACE {api}")) {
                Ok(r) => eprintln!("ce-door: restore {r}"),
                Err(e) => eprintln!("ce-door: restore {api}: {e}"),
            }
        }
    }
    // An autostart cell that fails to start is tried again after 1, 2, 4 ... 60 cycles (minutes), not every 60 s: a
    // binary that lost its exec bit (seen on 8 cells) filled the journal and the door's event log
    // with a start/fail pair per cell per minute for three days. A success, or an edit of the autostart file, resets it.
    let mut failing: HashMap<String, (u32, u32)> = HashMap::new(); // api -> (failures in a row, cycles to skip)
    loop {
        let a = autostart_set();
        failing.retain(|k, _| a.contains(k));
        for api in a {
            if let Some((_, skip)) = failing.get_mut(&api) {
                if *skip > 0 {
                    *skip -= 1;
                    continue;
                }
            }
            match ctl(&format!("PLACE {api}")) {
                Ok(r) if r.ends_with(": running") => {
                    failing.remove(&api);
                }
                Ok(r) if !r.starts_with("error") => {
                    failing.remove(&api);
                    eprintln!("ce-door: autostart {r}");
                }
                other => {
                    let f = failing.entry(api.clone()).or_insert((0, 0));
                    f.0 += 1;
                    f.1 = (1u32 << (f.0 - 1).min(6)).min(60) - 1;
                    let r = match other { Ok(r) => r, Err(e) => format!("{api}: {e}") };
                    eprintln!("ce-door: autostart {r} (failure {} in a row; next try in {} min)", f.0, f.1 + 1);
                }
            }
        }
        let up = running_now();
        if !up.is_empty() {
            seen.retain(|k, _| up.contains(k));
            let mut longlived: Vec<String> = Vec::new();
            for api in &up {
                let c = seen.entry(api.clone()).or_insert(0);
                *c += 1;
                if *c >= RESTORE_MIN_CYCLES {
                    longlived.push(api.clone());
                }
            }
            longlived.sort();
            // never an empty set over a good one, and never a half-written file: write a temp file, then rename
            if !longlived.is_empty() {
                let tmp = snap.with_extension("snapshot.tmp");
                if let Err(e) = std::fs::write(&tmp, longlived.join("\n")).and_then(|_| std::fs::rename(&tmp, &snap)) {
                    eprintln!("ce-door: snapshot {}: {e}", snap.display());
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

/// One control line to this machine's door, its answer back.
/// macOS application firewall pins an allowed app to its code signature. After this binary is replaced the old entry
/// no longer matches and every inbound door connection is accepted, then reset on its first data
/// (two stale entries: remote -> :7700 RST on net.mesh and the tailnet while loopback worked).
/// So at start: drop every entry for this path, add it again, allow it. Needs `sudo -n`; without it, say what to run.
#[cfg(target_os = "macos")]
fn firewall_self() {
    use std::process::Command;
    const FW: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";
    let Ok(me) = std::env::current_exe() else { return };
    let me = me.display().to_string();
    let on = Command::new(FW).arg("--getglobalstate").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("enabled")).unwrap_or(false);
    if !on {
        return;
    }
    let fw = |args: &[&str]| Command::new("sudo").args(["-n", FW]).args(args).output().map(|o| o.status.success()).unwrap_or(false);
    if !fw(&["--listapps"]) {
        eprintln!("ce-door: firewall on and no sudo -n: if remote calls are reset, run sudo {FW} --remove {me}; --add {me}; --unblockapp {me}");
        return;
    }
    for _ in 0..4 {
        if !fw(&["--remove", &me]) {
            break;
        }
    }
    let ok = fw(&["--add", &me]) && fw(&["--unblockapp", &me]);
    eprintln!("ce-door: application firewall entry for {me} {}", if ok { "renewed" } else { "NOT renewed" });
}

/// An unsigned binary (x86_64 links carry no signature; arm64 links are ad-hoc signed) gets no stable firewall entry:
/// after `--add` the first inbound connection passes and the next ones are reset (measured: 1 of 3, then
/// 6 of 6 once signed). So before binding: an unsigned door signs a copy ad-hoc, renames it over itself (the running
/// image keeps the old inode) and execs it with the same arguments; launchd keeps the pid.
#[cfg(target_os = "macos")]
fn sign_self() {
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    let Ok(me) = std::env::current_exe() else { return };
    let signed = Command::new("codesign").arg("-v").arg(&me).output().map(|o| o.status.success()).unwrap_or(true);
    if signed {
        return;
    }
    let tmp = me.with_extension("signing");
    let ok = std::fs::copy(&me, &tmp).is_ok()
        && Command::new("codesign").args(["-s", "-", "-f"]).arg(&tmp).output().map(|o| o.status.success()).unwrap_or(false)
        && std::fs::rename(&tmp, &me).is_ok();
    if !ok {
        std::fs::remove_file(&tmp).ok();
        eprintln!("ce-door: {} is unsigned and could not be signed ad-hoc; remote calls may be reset by the firewall", me.display());
        return;
    }
    eprintln!("ce-door: signed {} ad-hoc, restarting it", me.display());
    let e = Command::new(&me).args(std::env::args_os().skip(1)).exec();
    eprintln!("ce-door: exec {}: {e}", me.display());
}

fn ctl(line: &str) -> Result<String, String> {
    let mut s = std::os::unix::net::UnixStream::connect(door_sock()).map_err(|e| format!("door {}: {e}", door_sock().display()))?;
    s.write_all(format!("{line}\n").as_bytes()).map_err(|e| e.to_string())?;
    s.shutdown(std::net::Shutdown::Write).ok();
    let mut out = String::new();
    std::io::BufReader::new(s).read_to_string(&mut out).map_err(|e| e.to_string())?;
    Ok(out.trim_end().to_string())
}

/// A control line whose answer streams: print each line as it comes, until the door hangs up.
fn ctl_stream(line: &str) -> Result<String, String> {
    use std::io::BufRead;
    let mut s = std::os::unix::net::UnixStream::connect(door_sock()).map_err(|e| format!("door {}: {e}", door_sock().display()))?;
    s.write_all(format!("{line}\n").as_bytes()).map_err(|e| e.to_string())?;
    for l in std::io::BufReader::new(s).lines() {
        println!("{}", l.map_err(|e| e.to_string())?);
    }
    Ok(String::new())
}

/// Ask the door at `ip` to start `api` there: a spawning Hello with a self-signed `<api>:spawn` cap. The door starts
/// the cell and hands it the connection; the cell then refuses it (no op rights), which proves it runs.
fn place_remote(api: &str, ip: &str) -> Result<String, String> {
    let ip: IpAddr = ip.parse().map_err(|e| format!("{ip}: {e}"))?;
    let me = ce_gate::node_identity().map_err(|e| e.to_string())?;
    let chain = ce_gate::self_chain(&me, vec![format!("{api}:spawn")], 300);
    let hello = Hello { api: api.into(), version: 0, schema: 0, token: ce_gate::proof_for(&me, &chain, api, 0), spawn: true };
    let mut s = std::net::TcpStream::connect_timeout(&SocketAddr::new(ip, door_port()), std::time::Duration::from_secs(3)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(ce_wire::SPAWN_WAIT + std::time::Duration::from_secs(3))).ok();
    s.write_all(&frame(Kind::Hello, 0, 0, &ce_wire::postcard::to_stdvec(&hello).unwrap())).map_err(|e| e.to_string())?;
    let mut hb = [0u8; HEADER];
    s.read_exact(&mut hb).map_err(|e| format!("no answer from {ip}: {e}"))?;
    let h = ce_wire::Header::decode(&hb).map_err(|e| format!("{e:?}"))?;
    let mut p = vec![0u8; h.len as usize];
    s.read_exact(&mut p).map_err(|e| e.to_string())?;
    match ce_wire::postcard::from_bytes::<Refusal>(&p) {
        Ok(Refusal::NoCell(m)) => Err(format!("{ip}: {m}")),
        Ok(r) => Ok(format!("{api} runs on {ip} (its cell answered: {r:?})")),
        Err(e) => Err(format!("{ip}: undecodable answer {e}")),
    }
}

/// An address the door may listen on: loopback or a private overlay address, never 0.0.0.0 or a public one.
fn bindable(ip: IpAddr) -> bool {
    ip.is_loopback() || ce_wire::underlay::is_overlay(ip)
}

/// `ce-door bundle <identity>`: ~/Applications/ce.app around this binary, signed. Written to ce.app.new and renamed
/// over the old one, so a running door keeps its open file.
fn bundle(identity: &str) -> Result<String, String> {
    if !cfg!(target_os = "macos") {
        return Err("bundle: macOS only (the grant model it serves is macOS's)".into());
    }
    let me = std::env::current_exe().map_err(|e| format!("bundle: own path: {e}"))?;
    let home = std::env::var("HOME").map_err(|_| "bundle: HOME unset".to_string())?;
    let apps = std::path::Path::new(&home).join("Applications");
    let (app, new) = (apps.join("ce.app"), apps.join("ce.app.new"));
    let _ = std::fs::remove_dir_all(&new);
    let macos = new.join("Contents/MacOS");
    std::fs::create_dir_all(&macos).map_err(|e| format!("bundle: {}: {e}", macos.display()))?;
    std::fs::copy(&me, macos.join("ce-door")).map_err(|e| format!("bundle: copy {}: {e}", me.display()))?;
    let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.ce-net.ce</string>
<key>CFBundleName</key><string>ce</string>
<key>CFBundleExecutable</key><string>ce-door</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSUIElement</key><true/>
<key>NSScreenCaptureUsageDescription</key><string>ce cells read the operator display.</string>
<key>NSAppleEventsUsageDescription</key><string>ce cells drive apps on the operator display.</string>
</dict></plist>
"#;
    std::fs::write(new.join("Contents/Info.plist"), plist).map_err(|e| format!("bundle: Info.plist: {e}"))?;
    let o = std::process::Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", identity, "--identifier", "com.ce-net.ce"]).arg(&new)
        .output().map_err(|e| format!("bundle: codesign: {e}"))?;
    if !o.status.success() {
        return Err(format!("bundle: codesign -s {identity:?}: {}", String::from_utf8_lossy(&o.stderr).trim()));
    }
    let _ = std::fs::remove_dir_all(apps.join("ce.app.old"));
    if app.exists() {
        std::fs::rename(&app, apps.join("ce.app.old")).map_err(|e| format!("bundle: move old ce.app: {e}"))?;
    }
    std::fs::rename(&new, &app).map_err(|e| format!("bundle: {e}"))?;
    let _ = std::fs::remove_dir_all(apps.join("ce.app.old"));
    let dr = std::process::Command::new("/usr/bin/codesign").args(["-d", "-r-"]).arg(&app).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
    Ok(format!("{} signed by {identity}; {dr}\nrun it from launchd: ProgramArguments[0] = {}/Contents/MacOS/ce-door", app.display(), app.display()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn door_binds_only_loopback_and_overlay() {
        for a in ["127.0.0.1", "::1", "10.0.0.1", "100.64.9.1", "fd00::1"] {
            assert!(super::bindable(a.parse().unwrap()), "{a}");
        }
        for a in ["0.0.0.0", "::", "203.0.113.7", "8.8.8.8", "2001:db8::1"] {
            assert!(!super::bindable(a.parse().unwrap()), "{a}");
        }
    }
}
