//! The one function of `door.stranger-check`: say Hello to a door the way a stranger would, and report what it answered.
//! Every probe is one TCP connection, one Hello frame, one answer frame, each bounded by [`WAIT`]; nothing else is sent,
//! so a door that wrongly accepts is closed again before any op runs. A `ws://` or `wss://` address probes the same
//! way through a WebSocket door (wire.ws-door's public listener, wss://apps.ce-net.com/cap/wire): one message carries
//! one frame, and a socket the listener closes unread counts as refused.
use ce_gate::ce_identity::Identity;
use ce_wire::{frame, hello_payload, Header, Hello, Kind, Refusal, HEADER};
use door_stranger_check_api::*;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// How long one probe waits to connect, and then for the door's answer.
pub const WAIT: Duration = Duration::from_secs(8);
/// A name no cell has: a door must not start anything for it, least of all for a stranger.
pub const NEVER_A_CELL: &str = "stranger.never-a-cell";

/// The door's answer to one Hello: `Ok(refusal-or-ok)` when it answered, `Err(why)` when it did not.
pub fn hello(addr: &str, api: &str, schema: u64, token: Vec<u8>, spawn: bool) -> Result<Refusal, String> {
    let h = Hello { api: api.into(), version: 1, schema, token, spawn };
    let p = hello_payload(&h, WAIT).map_err(|e| format!("encode: {e}"))?;
    let f = frame(Kind::Hello, 0, 0, &p);
    if addr.starts_with("ws://") || addr.starts_with("wss://") {
        let url = addr.to_string();
        // a thread with its own runtime: check() is called from a CLI and from spawn_blocking in the cell
        return std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?
                .block_on(async { tokio::time::timeout(WAIT * 2, hello_ws(&url, f)).await.map_err(|_| "no answer: timeout".to_string())? })
        }).join().map_err(|_| "probe thread panicked".to_string())?;
    }
    let sa = addr.to_socket_addrs().map_err(|e| format!("resolve {addr}: {e}"))?.next().ok_or(format!("resolve {addr}: no address"))?;
    let mut s = TcpStream::connect_timeout(&sa, WAIT).map_err(|e| format!("connect: {e}"))?;
    s.set_read_timeout(Some(WAIT)).ok();
    s.set_write_timeout(Some(WAIT)).ok();
    s.write_all(&f).map_err(|e| format!("send: {e}"))?;
    let mut hb = [0u8; HEADER];
    s.read_exact(&mut hb).map_err(|e| format!("no answer: {e}"))?;
    let mut body = vec![0u8; Header::decode(&hb).map_err(|e| format!("bad header: {e:?}"))?.len as usize];
    s.read_exact(&mut body).map_err(|e| format!("short answer: {e}"))?;
    answer(&hb, &body)
}

/// One Hello frame as the first WebSocket message; the answer frame is the first binary message back.
async fn hello_ws(url: &str, f: Vec<u8>) -> Result<Refusal, String> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await.map_err(|e| format!("connect: {e}"))?;
    ws.send(Message::Binary(f.into())).await.map_err(|e| format!("send: {e}"))?;
    while let Some(m) = ws.next().await {
        match m {
            Ok(Message::Binary(b)) if b.len() >= HEADER => {
                let _ = ws.close(None).await;
                return answer(&b[..HEADER], &b[HEADER..]);
            }
            Ok(Message::Close(_)) | Err(_) => break,
            _ => {}
        }
    }
    Ok(Refusal::Decode("closed unread by the WebSocket door".into()))
}

fn answer(hb: &[u8], body: &[u8]) -> Result<Refusal, String> {
    let hd = Header::decode(hb.try_into().map_err(|_| "short header".to_string())?).map_err(|e| format!("bad header: {e:?}"))?;
    let body = body.get(..hd.len as usize).ok_or("short answer")?;
    let r: Refusal = ce_wire::postcard::from_bytes(body).map_err(|e| format!("undecodable answer: {e}"))?;
    Ok(match r {
        Refusal::Ok { .. } if hd.kind != Kind::Hello => Refusal::Decode(format!("Ok in a {:?} frame", hd.kind)),
        r => r,
    })
}

/// A fresh node key in a throwaway directory: nobody has granted it anything.
fn fresh_key() -> Result<Identity, String> {
    let d = std::env::temp_dir().join(format!("door-stranger-check-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|t| t.as_nanos()).unwrap_or(0)));
    let id = Identity::load_or_generate(&d).map_err(|e| format!("fresh key: {e}"));
    let _ = std::fs::remove_dir_all(&d);
    id
}

fn signed(id: &Identity, api: &str, schema: u64) -> Vec<u8> {
    ce_gate::proof_for(id, &ce_gate::self_chain(id, vec![format!("{api}:*")], 60), api, schema)
}

fn row(api: &str, who: &str, ans: Result<Refusal, String>, accept_is_ok: bool) -> Row {
    let (outcome, detail) = match ans {
        Ok(Refusal::Ok { .. }) => (if accept_is_ok { "ACCEPTED" } else { "OPEN" }, "Hello accepted".to_string()),
        Ok(r) => ("REFUSED", format!("{r:?}")),
        Err(e) => ("NO ANSWER", e),
    };
    Row { api: api.into(), who: who.into(), outcome: outcome.into(), detail: detail.chars().take(200).collect() }
}

pub fn check(r: CheckReq) -> Result<Report, CheckError> {
    if r.addr.is_empty() || r.apis.is_empty() {
        return Err(CheckError::Invalid("addr and at least one api are required".into()));
    }
    if r.apis.iter().any(|a| a.is_empty() || a.len() > 80) {
        return Err(CheckError::Invalid("an api name is empty or longer than 80".into()));
    }
    let stranger = fresh_key().map_err(CheckError::Invalid)?;
    let own = if r.control { ce_gate::node_identity().ok() } else { None };
    let mut rows = Vec::new();
    for api in &r.apis {
        // 1. the schema, from the refusal of a Hello that carries schema 0
        let schema = match hello(&r.addr, api, 0, Vec::new(), false) {
            Ok(Refusal::Schema { ours, .. }) | Ok(Refusal::SchemaAt { ours, .. }) => ours,
            other => {
                let mut x = row(api, "anonymous", other, false);
                if x.outcome == "REFUSED" {
                    x.outcome = "SCHEMA ?".into();
                }
                rows.push(x);
                continue;
            }
        };
        rows.push(row(api, "anonymous", hello(&r.addr, api, schema, Vec::new(), false), false));
        rows.push(row(api, "stranger", hello(&r.addr, api, schema, signed(&stranger, api, schema), false), false));
        rows.push(row(api, "stranger-spawn", hello(&r.addr, api, schema, signed(&stranger, api, schema), true), false));
        if let Some(me) = &own {
            rows.push(row(api, "own-key", hello(&r.addr, api, schema, signed(me, api, schema), false), true));
        }
    }
    rows.push(row(NEVER_A_CELL, "stranger-spawn", hello(&r.addr, NEVER_A_CELL, 1, signed(&stranger, NEVER_A_CELL, 1), true), false));
    let open = rows.iter().any(|x| x.outcome == "OPEN");
    let unsure = rows.iter().any(|x| x.outcome == "NO ANSWER" || x.outcome == "SCHEMA ?")
        || (r.control && rows.iter().any(|x| x.who == "own-key" && x.outcome != "ACCEPTED"))
        || (r.control && own.is_none());
    let verdict = if open { "OPEN" } else if unsure { "INCONCLUSIVE" } else { "PASS" };
    Ok(Report { addr: r.addr, verdict: verdict.into(), rows })
}

/// The report as lines, last line `RESULT <verdict>`.
pub fn render(rep: &Report) -> String {
    let mut s = String::new();
    for x in &rep.rows {
        s.push_str(&format!("{:28} {:14} {:10} {}\n", x.api, x.who, x.outcome, x.detail));
    }
    s.push_str(&format!("RESULT {} ({})\n", rep.verdict, rep.addr));
    s
}
