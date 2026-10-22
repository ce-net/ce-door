//! Underlay networks: the private overlays a door listens on and finds its peers through. No
//! lock-in: tailscale, ce-scale, netbird, zerotier or any other overlay works, alone or together.
//!
//! Each network gives this machine's addresses on it and the peers it can see:
//! - `ce-scale` (alias `netmesh`, `net.mesh`): `ip -4 -o addr show nm0` (Linux), else the `addr` of `netmesh peers`;
//!   peers from `netmesh peers --control $NETMESH_CONTROL` (`$CE_NETMESH` or `netmesh`), with their ce node ids.
//!   Skipped when `NETMESH_CONTROL` is unset, as before.
//! - `tailscale`: `tailscale ip -4`; peers from `tailscale status --json` (online, not shared in from another tailnet).
//! - `netbird`: `netbird status --json` (`netbirdIp` and the connected peers).
//! - `zerotier`: `zerotier-cli -j listnetworks` (assigned addresses). ZeroTier's CLI does not list the peers' managed
//!   addresses, so zerotier peers go in `peers.static`.
//! - `static`: `~/.config/ce-wire/peers.static`, `<ip> [node id hex]` per line, `#` comments. Hand-written peers.
//!
//! `$CE_NET` picks the networks and their order (comma list, e.g. `tailscale,static`); unset, empty or `all` means all
//! of them in the order above. A missing CLI is skipped silently; every CLI call has a [`CLI_TIMEOUT`].
//!
//! Trust: a node id in the peers file roots ce-cap chains (`ce_gate::mesh_roots`), so ids come only
//! from ce-scale (the netmesh control server admits them) and `peers.static` (written by this machine's owner). The
//! other networks give addresses only.
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Longest a network CLI may run before it is killed and the network counts as down this round.
pub const CLI_TIMEOUT: Duration = Duration::from_secs(5);
/// A network whose CLI fails keeps its last good peers this long, so one slow `tailscale status` does not drop its
/// peers from the file for a minute.
pub const KEEP_LAST_GOOD: Duration = Duration::from_secs(600);

/// One underlay network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Net {
    CeScale,
    Tailscale,
    Netbird,
    Zerotier,
    Static,
}

impl Net {
    /// Every network, in the default order (ce-scale first: its peers carry node ids).
    pub const ALL: [Net; 5] = [Net::CeScale, Net::Tailscale, Net::Netbird, Net::Zerotier, Net::Static];

    pub fn name(self) -> &'static str {
        match self {
            Net::CeScale => "ce-scale",
            Net::Tailscale => "tailscale",
            Net::Netbird => "netbird",
            Net::Zerotier => "zerotier",
            Net::Static => "static",
        }
    }

    pub fn parse(s: &str) -> Option<Net> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "ce-scale" | "ce/scale" | "cescale" | "ce_scale" | "netmesh" | "net.mesh" | "net-mesh" => Net::CeScale,
            "tailscale" | "ts" => Net::Tailscale,
            "netbird" | "nb" => Net::Netbird,
            "zerotier" | "zt" => Net::Zerotier,
            "static" => Net::Static,
            _ => return None,
        })
    }
}

/// A peer machine seen on one network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    /// The address its door is dialed on.
    pub ip: IpAddr,
    /// Its ce node id (hex), when the network vouches for one (ce-scale, static).
    pub node: Option<String>,
    /// Other addresses of the same machine (netmesh endpoints, a tailscale node's IPv6): a later network's peer on one
    /// of these is the same machine and is dropped by [`merge`].
    pub also: Vec<IpAddr>,
    pub net: Net,
    /// A host name, for the peers file comment only.
    pub name: Option<String>,
}

impl Peer {
    fn new(net: Net, ip: IpAddr) -> Peer {
        Peer { ip, node: None, also: Vec::new(), net, name: None }
    }
}

/// The networks `$CE_NET` names, in its order.
pub fn enabled() -> Vec<Net> {
    parse_list(&std::env::var("CE_NET").unwrap_or_default())
}

/// `$CE_NET` text to networks: comma (or space) list, unknown names said and skipped, duplicates dropped; empty or
/// `all` is [`Net::ALL`].
pub fn parse_list(s: &str) -> Vec<Net> {
    let mut out = Vec::new();
    for w in s.split(|c: char| c == ',' || c.is_whitespace()).filter(|w| !w.is_empty()) {
        if w.eq_ignore_ascii_case("all") {
            return Net::ALL.to_vec();
        }
        match Net::parse(w) {
            Some(n) if !out.contains(&n) => out.push(n),
            Some(_) => {}
            None => eprintln!("ce-wire: CE_NET names unknown network {w:?}; known: ce-scale tailscale netbird zerotier static"),
        }
    }
    if out.is_empty() {
        Net::ALL.to_vec()
    } else {
        out
    }
}

/// True for an address a door may listen on besides loopback: a private overlay range. IPv4 10/8, 172.16/12,
/// 192.168/16 (RFC 1918) and 100.64/10 (CGNAT: tailscale, netbird); IPv6 fc00::/7 (ULA: tailscale, zerotier).
/// Never the unspecified address, never a public one.
pub fn is_overlay(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            a.is_private() || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => is_overlay(IpAddr::V4(v4)),
            None => (a.segments()[0] & 0xfe00) == 0xfc00,
        },
    }
}

/// The addresses a door listens on: loopback, then every overlay address of the enabled networks (deduplicated,
/// non-overlay ones dropped and said).
pub fn door_binds(port: u16) -> Vec<(Option<Net>, std::net::SocketAddr)> {
    let mut out = vec![(None, std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))];
    for (net, ip) in local_addrs() {
        if !out.iter().any(|(_, a)| a.ip() == ip) {
            out.push((Some(net), std::net::SocketAddr::new(ip, port)));
        }
    }
    out
}

/// This machine's overlay addresses on every enabled network, first network first. Public, unspecified and loopback
/// addresses are never returned.
pub fn local_addrs() -> Vec<(Net, IpAddr)> {
    let mut out: Vec<(Net, IpAddr)> = Vec::new();
    for net in enabled() {
        for ip in local_on(net) {
            if !is_overlay(ip) {
                eprintln!("ce-wire: {} reports {ip}, not a private overlay address; the door does not listen there", net.name());
            } else if !out.iter().any(|(_, a)| *a == ip) {
                out.push((net, ip));
            }
        }
    }
    out
}

fn local_on(net: Net) -> Vec<IpAddr> {
    match net {
        Net::CeScale => {
            let nm0 = run("ip", &["-4", "-o", "addr", "show", "nm0"]).and_then(|s| parse_ip_addr(&s));
            match nm0 {
                Some(ip) => vec![ip],
                None => netmesh_peers().and_then(|t| parse_netmesh_peers(&t).0).into_iter().collect(),
            }
        }
        Net::Tailscale => run_any(&tailscale_bins(), &["ip", "-4"]).map(|s| parse_tailscale_ips(&s)).unwrap_or_default(),
        Net::Netbird => run_any(&netbird_bins(), &["status", "--json"]).map(|s| parse_netbird_status(&s).0).unwrap_or_default(),
        Net::Zerotier => run_any(&zerotier_bins(), &["-j", "listnetworks"]).map(|s| parse_zerotier_networks(&s)).unwrap_or_default(),
        Net::Static => Vec::new(),
    }
}

/// One network's peers now. `None`: the network did not answer (CLI missing, down, timed out, no peers on ce-scale).
pub fn peers_on(net: Net) -> Option<Vec<Peer>> {
    match net {
        Net::CeScale => {
            let p = parse_netmesh_peers(&netmesh_peers()?).1;
            if p.is_empty() {
                eprintln!("ce-door: netmesh peers returned no peers");
                return None;
            }
            Some(p)
        }
        Net::Tailscale => Some(parse_tailscale_status(&run_any(&tailscale_bins(), &["status", "--json"])?)),
        Net::Netbird => Some(parse_netbird_status(&run_any(&netbird_bins(), &["status", "--json"])?).1),
        Net::Zerotier => None,
        Net::Static => Some(parse_static(&std::fs::read_to_string(static_file()).ok()?)),
    }
}

/// Every enabled network's peers, merged ([`merge`]). A network that does not answer contributes its last good list
/// for [`KEEP_LAST_GOOD`].
pub fn peers() -> Vec<Peer> {
    type LastGood = HashMap<Net, (Instant, Vec<Peer>)>;
    static LAST: Mutex<Option<LastGood>> = Mutex::new(None);
    let lists: Vec<Vec<Peer>> = enabled()
        .into_iter()
        .filter_map(|net| {
            let now = peers_on(net);
            let mut g = LAST.lock().unwrap_or_else(|e| e.into_inner());
            let m = g.get_or_insert_with(HashMap::new);
            match now {
                Some(p) => {
                    m.insert(net, (Instant::now(), p.clone()));
                    Some(p)
                }
                None => match m.get(&net) {
                    Some((t, p)) if t.elapsed() < KEEP_LAST_GOOD => Some(p.clone()),
                    _ => {
                        m.remove(&net);
                        None
                    }
                },
            }
        })
        .collect();
    merge(lists)
}

/// Merge peer lists, first list first. A peer whose address was already seen is dropped. A peer that is the same
/// machine by one of its `also` addresses or its node id, but has an address of its own, stays as a second path to that
/// machine, carrying the first network's node id: `by_name` dials every path of a provider at once, so a machine whose
/// ce-scale link is down is still reached over tailscale or netbird (seen: mesh down after a reboot,
/// tailscale up, and the tailscale line was dropped, so no cell on it answered).
pub fn merge(lists: Vec<Vec<Peer>>) -> Vec<Peer> {
    let mut ips: HashSet<IpAddr> = HashSet::new();
    let mut owner: std::collections::HashMap<IpAddr, Option<String>> = std::collections::HashMap::new();
    let mut ids: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for mut p in lists.into_iter().flatten() {
        if ips.contains(&p.ip) {
            continue;
        }
        // same machine as an earlier line: its address is one of that line's endpoints, one of its own endpoints is
        // an earlier address, or the node ids match
        let same = std::iter::once(&p.ip)
            .chain(p.also.iter())
            .find_map(|a| owner.get(a).cloned())
            .or_else(|| p.node.as_ref().filter(|n| ids.contains(*n)).map(|n| Some(n.clone())));
        if let Some(id) = same {
            // a second path: keep it with the machine's id (None when the first network gave no id either)
            p.node = id.or(p.node);
            p.also.clear();
        }
        ips.insert(p.ip);
        owner.insert(p.ip, p.node.clone());
        for a in &p.also {
            // an endpoint is not a dialled line: a later network may still list it as its own address
            owner.entry(*a).or_insert_with(|| p.node.clone());
        }
        if let Some(n) = &p.node {
            ids.insert(n.clone());
        }
        out.push(p);
    }
    out
}

/// The peers file text: `<ip> [node id] # <network> [name]` per line (`ce_wire::mesh_peer_ids` reads it).
pub fn render(peers: &[Peer]) -> String {
    let mut s = String::new();
    for p in peers {
        s.push_str(&p.ip.to_string());
        if let Some(n) = &p.node {
            s.push(' ');
            s.push_str(n);
        }
        s.push_str(" # ");
        s.push_str(p.net.name());
        if let Some(n) = &p.name {
            s.push(' ');
            s.push_str(n);
        }
        s.push('\n');
    }
    s
}

/// Hand-written peers: `~/.config/ce-wire/peers.static`.
pub fn static_file() -> PathBuf {
    crate::peers_file().with_file_name("peers.static")
}

/// Rewrite the peers file from every enabled network. The old file stays when no network has a peer. A peers file
/// that was hand-written (no `NETMESH_CONTROL`, so no door wrote it) is first copied to `peers.static`, once, so a
/// door that now also sees tailscale does not drop it.
pub fn refresh_peers_file() {
    let f = crate::peers_file();
    keep_hand_written(&f, &static_file(), std::env::var_os("NETMESH_CONTROL").is_some());
    let peers = peers();
    if peers.is_empty() {
        return;
    }
    let text = render(&peers);
    if std::fs::read_to_string(&f).is_ok_and(|old| old == text) {
        return;
    }
    let _ = std::fs::create_dir_all(f.parent().unwrap_or(Path::new(".")));
    let tmp = f.with_extension("tmp");
    if std::fs::write(&tmp, text).is_ok() {
        let _ = std::fs::rename(tmp, f);
    }
}

fn keep_hand_written(peers: &Path, stat: &Path, netmesh: bool) {
    if netmesh || stat.exists() {
        return;
    }
    let Ok(old) = std::fs::read_to_string(peers) else { return };
    // A file this code wrote has a "# <network>" comment on every line.
    let ours = !old.trim().is_empty() && old.lines().filter(|l| !l.trim().is_empty()).all(|l| Net::ALL.iter().any(|n| l.contains(&format!("# {}", n.name()))));
    if !ours && !old.trim().is_empty() {
        let _ = std::fs::write(stat, old);
        eprintln!("ce-door: kept the hand-written {} as {}", peers.display(), stat.display());
    }
}

// ---- parsers: pure functions over the CLIs' text ----

fn json(txt: &str) -> Option<serde_json::Value> {
    let i = txt.find(['{', '['])?;
    serde_json::from_str(&txt[i..]).ok()
}

fn ip_of(s: &str) -> Option<IpAddr> {
    let s = s.split('#').next()?.trim();
    let s = s.split('/').next()?;
    s.parse::<IpAddr>().ok().or_else(|| s.parse::<std::net::SocketAddr>().ok().map(|a| a.ip()))
}

/// `ip -4 -o addr show <if>`: the first `inet` address.
pub fn parse_ip_addr(txt: &str) -> Option<IpAddr> {
    txt.split_whitespace().skip_while(|w| *w != "inet").nth(1)?.split('/').next()?.parse().ok()
}

/// `netmesh peers --control ...`: (this node's mesh address, the peers with node ids; endpoints become `also`).
pub fn parse_netmesh_peers(txt: &str) -> (Option<IpAddr>, Vec<Peer>) {
    let Some(v) = json(txt) else { return (None, Vec::new()) };
    let me = v.get("addr").and_then(|a| a.as_str()).and_then(ip_of);
    let peers = v
        .get("peers")
        .and_then(|p| p.as_array())
        .into_iter()
        .flatten()
        .filter_map(|p| {
            let node = p.get("node")?.as_str()?.to_string();
            let mut peer = Peer::new(Net::CeScale, ip_of(p.get("addr")?.as_str()?)?);
            peer.node = Some(node);
            peer.name = p.get("name").and_then(|n| n.as_str()).map(str::to_string);
            peer.also = p.get("endpoints").and_then(|e| e.as_array()).into_iter().flatten().filter_map(|e| ip_of(e.as_str()?)).collect();
            Some(peer)
        })
        .collect();
    (me, peers)
}

/// `tailscale ip -4`: one address per line.
pub fn parse_tailscale_ips(txt: &str) -> Vec<IpAddr> {
    txt.lines().filter_map(|l| l.trim().parse().ok()).collect()
}

/// `tailscale status --json`: every online peer that is not shared in from another tailnet (`ShareeNode`), dialed on
/// its first IPv4 (else first) Tailscale IP.
pub fn parse_tailscale_status(txt: &str) -> Vec<Peer> {
    let Some(v) = json(txt) else { return Vec::new() };
    let mut out: Vec<Peer> = v
        .get("Peer")
        .and_then(|p| p.as_object())
        .into_iter()
        .flat_map(|m| m.values())
        .filter(|p| p.get("Online").and_then(|o| o.as_bool()).unwrap_or(false))
        .filter(|p| !p.get("ShareeNode").and_then(|o| o.as_bool()).unwrap_or(false))
        .filter_map(|p| {
            let ips: Vec<IpAddr> = p.get("TailscaleIPs")?.as_array()?.iter().filter_map(|a| ip_of(a.as_str()?)).collect();
            let ip = ips.iter().find(|a| a.is_ipv4()).or(ips.first()).copied()?;
            let mut peer = Peer::new(Net::Tailscale, ip);
            peer.also = ips.into_iter().filter(|a| *a != ip).collect();
            peer.name = p.get("HostName").and_then(|n| n.as_str()).filter(|n| !n.is_empty()).map(str::to_string);
            Some(peer)
        })
        .collect();
    out.sort_by_key(|p| p.ip); // Peer is a JSON object: give the file a stable order
    out
}

/// `netbird status --json`: (this node's `netbirdIp`, the connected peers' `netbirdIp`).
pub fn parse_netbird_status(txt: &str) -> (Vec<IpAddr>, Vec<Peer>) {
    let Some(v) = json(txt) else { return (Vec::new(), Vec::new()) };
    let me = v.get("netbirdIp").and_then(|a| a.as_str()).and_then(ip_of).into_iter().collect();
    let peers = v
        .pointer("/peers/details")
        .and_then(|d| d.as_array())
        .into_iter()
        .flatten()
        .filter(|p| p.get("status").and_then(|s| s.as_str()).is_some_and(|s| s.eq_ignore_ascii_case("connected")))
        .filter_map(|p| {
            let mut peer = Peer::new(Net::Netbird, ip_of(p.get("netbirdIp")?.as_str()?)?);
            peer.name = p.get("fqdn").and_then(|n| n.as_str()).and_then(|n| n.split('.').next()).filter(|n| !n.is_empty()).map(str::to_string);
            Some(peer)
        })
        .collect();
    (me, peers)
}

/// `zerotier-cli -j listnetworks`: the assigned addresses of every network whose status is OK.
pub fn parse_zerotier_networks(txt: &str) -> Vec<IpAddr> {
    let Some(v) = json(txt) else { return Vec::new() };
    v.as_array()
        .into_iter()
        .flatten()
        .filter(|n| n.get("status").and_then(|s| s.as_str()).is_none_or(|s| s == "OK"))
        .flat_map(|n| n.get("assignedAddresses").and_then(|a| a.as_array()).cloned().unwrap_or_default())
        .filter_map(|a| ip_of(a.as_str()?))
        .collect()
}

/// `peers.static`: `<ip>[:port] [node id hex]` per line, `#` comments, like the peers file.
pub fn parse_static(txt: &str) -> Vec<Peer> {
    txt.lines()
        .filter_map(|l| {
            let mut w = l.split('#').next()?.split_whitespace();
            let host = w.next()?;
            let Some(ip) = ip_of(host) else {
                eprintln!("ce-wire: peers.static {host:?} is not an ip address; skipped");
                return None;
            };
            let mut p = Peer::new(Net::Static, ip);
            p.node = w.next().map(str::to_string);
            Some(p)
        })
        .collect()
}

// ---- CLIs ----

fn netmesh_peers() -> Option<String> {
    let control = std::env::var("NETMESH_CONTROL").ok()?;
    let bin = std::env::var("CE_NETMESH").unwrap_or_else(|_| "netmesh".into());
    match run_out(&bin, &["peers", "--control", &control], CLI_TIMEOUT) {
        Ran::Ok(s) => Some(s),
        Ran::Missing => {
            eprintln!("ce-door: {bin} peers: not found");
            None
        }
        Ran::Failed(e) => {
            eprintln!("ce-door: {bin} peers: {e}");
            None
        }
    }
}

fn bins(env: &str, name: &str, mac: &[&str]) -> Vec<String> {
    if let Ok(b) = std::env::var(env) {
        return vec![b];
    }
    let mut v = vec![name.to_string()];
    if cfg!(target_os = "macos") {
        v.extend(mac.iter().map(|s| s.to_string()));
    }
    v
}

fn tailscale_bins() -> Vec<String> {
    bins("CE_TAILSCALE", "tailscale", &["/Applications/Tailscale.app/Contents/MacOS/Tailscale", "/usr/local/bin/tailscale", "/opt/homebrew/bin/tailscale"])
}

fn netbird_bins() -> Vec<String> {
    bins("CE_NETBIRD", "netbird", &["/Applications/NetBird.app/Contents/MacOS/netbird", "/usr/local/bin/netbird", "/opt/homebrew/bin/netbird"])
}

fn zerotier_bins() -> Vec<String> {
    bins("CE_ZEROTIER", "zerotier-cli", &["/Library/Application Support/ZeroTier/One/zerotier-cli", "/usr/local/bin/zerotier-cli"])
}

/// The first of `bins` that exists, run with `args`; its stdout when it exits 0 within [`CLI_TIMEOUT`].
fn run_any(bins: &[String], args: &[&str]) -> Option<String> {
    for b in bins {
        match run_out(b, args, CLI_TIMEOUT) {
            Ran::Ok(s) => return Some(s),
            Ran::Missing => continue,
            Ran::Failed(_) => return None,
        }
    }
    None
}

fn run(bin: &str, args: &[&str]) -> Option<String> {
    match run_out(bin, args, CLI_TIMEOUT) {
        Ran::Ok(s) => Some(s),
        _ => None,
    }
}

enum Ran {
    Ok(String),
    Missing,
    Failed(String),
}

/// Run a CLI with a deadline: stdout is read on a thread (a full pipe cannot stall the wait), the child is killed and
/// reaped at the deadline.
fn run_out(bin: &str, args: &[&str], timeout: Duration) -> Ran {
    use std::io::Read;
    use std::process::{Command, Stdio};
    let mut child = match Command::new(bin).args(args).env("TAILSCALE_BE_CLI", "1").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ran::Missing,
        Err(e) => return Ran::Failed(e.to_string()),
    };
    let start = Instant::now();
    let (mut out, mut err) = (child.stdout.take(), child.stderr.take());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut s = Vec::new();
        let mut e = Vec::new();
        if let Some(o) = out.as_mut() {
            let _ = o.take(4 << 20).read_to_end(&mut s);
        }
        if let Some(r) = err.as_mut() {
            let _ = r.take(64 << 10).read_to_end(&mut e);
        }
        let _ = tx.send((s, e));
    });
    let got = rx.recv_timeout(timeout);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if got.is_ok() && start.elapsed() < timeout => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    match (got, status) {
        (Ok((s, _)), Some(st)) if st.success() => Ran::Ok(String::from_utf8_lossy(&s).into_owned()),
        (Ok((_, e)), Some(st)) => Ran::Failed(format!("{st}: {}", String::from_utf8_lossy(&e).trim())),
        _ => Ran::Failed(format!("no answer in {} s, killed", timeout.as_secs())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    const NETMESH: &str = r#"{
  "ok": true,
  "addr": "10.0.0.1",
  "peers": [
    { "node": "aa0001", "wg": "x=", "addr": "10.0.0.2",
      "endpoints": ["100.64.11.2:51877", "10.1.0.1:51877", "192.168.0.10:51877#lan"], "last_seen": 1, "name": "node-a" },
    { "node": "bb0002", "wg": "y=", "addr": "10.0.0.3", "endpoints": ["100.64.12.3:51877"], "name": "node-b" },
    { "wg": "no node id", "addr": "10.0.0.9" }
  ]
}"#;

    const TAILSCALE: &str = r#"{
  "BackendState": "Running",
  "Self": { "HostName": "node-c", "TailscaleIPs": ["100.64.9.1", "fd00::9:1"], "Online": true },
  "Peer": {
    "nodekey:a": { "HostName": "node-a", "TailscaleIPs": ["100.64.11.2", "fd00::1"], "Online": true },
    "nodekey:b": { "HostName": "node-d", "TailscaleIPs": ["100.64.11.4"], "Online": false },
    "nodekey:c": { "HostName": "friend", "TailscaleIPs": ["100.64.8.1"], "Online": true, "ShareeNode": true },
    "nodekey:d": { "HostName": "pi", "TailscaleIPs": ["fd00::7", "100.64.0.7"], "Online": true }
  }
}"#;

    const NETBIRD: &str = r#"{
  "peers": { "total": 3, "connected": 2, "details": [
    { "fqdn": "box-a.netbird.cloud", "netbirdIp": "100.92.1.2", "status": "Connected" },
    { "fqdn": "box-b.netbird.cloud", "netbirdIp": "100.92.1.3", "status": "Idle" },
    { "fqdn": "box-c.netbird.cloud", "netbirdIp": "100.92.1.4/32", "status": "Connected" }
  ] },
  "netbirdIp": "100.92.0.1/16",
  "fqdn": "me.netbird.cloud"
}"#;

    const ZEROTIER: &str = r#"[
  { "nwid": "8056c2e21c000001", "status": "OK", "portDeviceName": "ztabc",
    "assignedAddresses": ["10.147.17.5/24", "fd80:56c2:e21c:0:199:9300:aa:bb/88"] },
  { "nwid": "dead", "status": "ACCESS_DENIED", "assignedAddresses": ["10.9.9.9/24"] }
]"#;

    #[test]
    fn ce_net_list_order_aliases_and_default() {
        assert_eq!(parse_list(""), Net::ALL.to_vec());
        assert_eq!(parse_list("all"), Net::ALL.to_vec());
        assert_eq!(parse_list("tailscale, netmesh"), vec![Net::Tailscale, Net::CeScale]);
        assert_eq!(parse_list("ce/scale,static,ce-scale"), vec![Net::CeScale, Net::Static]);
        assert_eq!(parse_list("bogus"), Net::ALL.to_vec());
        assert_eq!(parse_list("zt,nb,bogus"), vec![Net::Zerotier, Net::Netbird]);
    }

    #[test]
    fn overlay_ranges_only() {
        for a in ["10.0.0.1", "100.64.9.1", "100.127.255.255", "172.16.0.1", "192.168.0.5", "fd00::1", "fc00::1"] {
            assert!(is_overlay(ip(a)), "{a}");
        }
        for a in ["0.0.0.0", "::", "127.0.0.1", "::1", "8.8.8.8", "100.63.0.1", "100.128.0.1", "203.0.113.7", "2001:db8::1", "fe80::1", "169.254.1.1", "::ffff:8.8.8.8"] {
            assert!(!is_overlay(ip(a)), "{a}");
        }
        assert!(is_overlay(ip("::ffff:10.0.0.1")));
    }

    #[test]
    fn ip_addr_output() {
        let t = "7: nm0    inet 10.0.0.1/16 scope global nm0\\       valid_lft forever preferred_lft forever\n";
        assert_eq!(parse_ip_addr(t), Some(ip("10.0.0.1")));
        assert_eq!(parse_ip_addr(""), None);
    }

    #[test]
    fn netmesh_peers_keep_ids_and_endpoints() {
        let (me, p) = parse_netmesh_peers(NETMESH);
        assert_eq!(me, Some(ip("10.0.0.1")));
        assert_eq!(p.len(), 2, "a peer without a node id is skipped, as before");
        assert_eq!(p[0].ip, ip("10.0.0.2"));
        assert_eq!(p[0].node.as_deref(), Some("aa0001"));
        assert_eq!(p[0].also, vec![ip("100.64.11.2"), ip("10.1.0.1"), ip("192.168.0.10")]);
        assert_eq!(p[1].name.as_deref(), Some("node-b"));
        // a log line before the JSON does not break it
        assert_eq!(parse_netmesh_peers(&format!("warn: slow\n{NETMESH}")).1.len(), 2);
        assert_eq!(parse_netmesh_peers("garbage").1, vec![]);
    }

    #[test]
    fn netmesh_file_lines_same_as_before() {
        let text = render(&parse_netmesh_peers(NETMESH).1);
        assert_eq!(text, "10.0.0.2 aa0001 # ce-scale node-a\n10.0.0.3 bb0002 # ce-scale node-b\n");
        // mesh_peer_ids reads that back to the old (ip, id) pairs
        let back: Vec<(IpAddr, Option<String>)> = parse_static(&text).into_iter().map(|p| (p.ip, p.node)).collect();
        assert_eq!(back, vec![(ip("10.0.0.2"), Some("aa0001".into())), (ip("10.0.0.3"), Some("bb0002".into()))]);
    }

    #[test]
    fn tailscale_ip_and_status() {
        assert_eq!(parse_tailscale_ips("100.64.9.1\n"), vec![ip("100.64.9.1")]);
        let p = parse_tailscale_status(TAILSCALE);
        let ips: Vec<String> = p.iter().map(|p| p.ip.to_string()).collect();
        assert_eq!(ips, ["100.64.0.7", "100.64.11.2"], "offline and shared-in peers skipped, IPv4 preferred");
        assert!(p.iter().all(|p| p.node.is_none()), "tailscale vouches for no ce node id");
        assert_eq!(p[1].also, vec![ip("fd00::1")]);
        assert_eq!(p[0].name.as_deref(), Some("pi"));
        assert!(parse_tailscale_status("{}").is_empty());
    }

    #[test]
    fn netbird_status() {
        let (me, p) = parse_netbird_status(NETBIRD);
        assert_eq!(me, vec![ip("100.92.0.1")]);
        let ips: Vec<String> = p.iter().map(|p| p.ip.to_string()).collect();
        assert_eq!(ips, ["100.92.1.2", "100.92.1.4"]);
        assert_eq!(p[0].name.as_deref(), Some("box-a"));
    }

    #[test]
    fn zerotier_networks() {
        assert_eq!(parse_zerotier_networks(ZEROTIER), vec![ip("10.147.17.5"), ip("fd80:56c2:e21c:0:199:9300:aa:bb")]);
        assert!(parse_zerotier_networks("[]").is_empty());
    }

    #[test]
    fn static_file_lines() {
        let p = parse_static("# hand\n10.0.0.5 abcd\n192.168.0.9:7700\nnot-a-host\n\n");
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].node.as_deref(), Some("abcd"));
        assert_eq!(p[1].ip, ip("192.168.0.9"));
    }

    #[test]
    fn merge_first_network_wins_by_ip_alias_and_id() {
        let mesh = parse_netmesh_peers(NETMESH).1;
        let ts = parse_tailscale_status(TAILSCALE);
        let st = parse_static("10.0.0.2 zzz\n10.5.5.5 bb0002\n10.6.6.6 newid\n");
        let m = merge(vec![mesh, ts, st]);
        let got: Vec<(String, Net)> = m.iter().map(|p| (p.ip.to_string(), p.net)).collect();
        assert_eq!(
            got,
            vec![
                ("10.0.0.2".into(), Net::CeScale),
                ("10.0.0.3".into(), Net::CeScale),
                // 100.64.11.2 is a netmesh endpoint of node-a: kept as its second path (below)
                ("100.64.0.7".into(), Net::Tailscale),
                ("100.64.11.2".into(), Net::Tailscale),
                // 10.0.0.2 (same ip) dropped; 10.5.5.5 has node-b's node id: a second path to it
                ("10.5.5.5".into(), Net::Static),
                ("10.6.6.6".into(), Net::Static),
            ]
        );
    }

    #[test]
    fn second_path_carries_the_machine_id() {
        let m = merge(vec![parse_netmesh_peers(NETMESH).1, parse_tailscale_status(TAILSCALE)]);
        let mac: Vec<(String, Option<String>)> =
            m.iter().filter(|p| p.node.as_deref() == Some("aa0001")).map(|p| (p.ip.to_string(), p.node.clone())).collect();
        // the mesh line first, then the tailscale one: by_name matches both by id and dials them together
        assert_eq!(mac, vec![("10.0.0.2".into(), Some("aa0001".into())), ("100.64.11.2".into(), Some("aa0001".into()))]);
        let file = render(&m);
        assert!(file.contains("100.64.11.2 aa0001 # tailscale node-a\n"), "{file}");
        // a second path never adds its own aliases: the tailscale IPv6 of node-a is not a third line
        assert!(!file.contains("fd00::1"), "{file}");
    }

    #[test]
    fn hand_written_peers_kept_once() {
        let d = std::env::temp_dir().join(format!("ce-underlay-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let (peers, stat) = (d.join("peers"), d.join("peers.static"));
        std::fs::write(&peers, "10.0.0.5 abcd\n").unwrap();
        keep_hand_written(&peers, &stat, true);
        assert!(!stat.exists(), "netmesh wrote it: not hand-written");
        keep_hand_written(&peers, &stat, false);
        assert_eq!(std::fs::read_to_string(&stat).unwrap(), "10.0.0.5 abcd\n");
        std::fs::remove_file(&stat).unwrap();
        std::fs::write(&peers, "100.64.0.7 # tailscale pi\n").unwrap();
        keep_hand_written(&peers, &stat, false);
        assert!(!stat.exists(), "a file this code wrote is not copied");
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// `cargo test -p ce-wire underlay::tests::live -- --ignored --nocapture`: what this machine's door would bind and dial.
    #[test]
    #[ignore]
    fn live() {
        for (n, a) in door_binds(7700) {
            println!("bind {a} {}", n.map_or("loopback", |n| n.name()));
        }
        print!("{}", render(&peers()));
    }

    #[test]
    fn cli_missing_and_timeout() {
        assert!(matches!(run_out("ce-no-such-cli-xyz", &[], CLI_TIMEOUT), Ran::Missing));
        let t = Instant::now();
        assert!(matches!(run_out("sleep", &["5"], Duration::from_millis(200)), Ran::Failed(_)));
        assert!(t.elapsed() < Duration::from_secs(2), "killed at the deadline");
        assert!(matches!(run_out("echo", &["hi"], CLI_TIMEOUT), Ran::Ok(s) if s == "hi\n"));
        assert!(matches!(run_out("false", &[], CLI_TIMEOUT), Ran::Failed(_)));
        assert_eq!(run_any(&["ce-no-such-cli-xyz".into(), "echo".into()], &["x"]).as_deref(), Some("x\n"));
    }
}
