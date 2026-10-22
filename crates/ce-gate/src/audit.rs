//! The per-node audit chain: one JSON row per answered call or app event,
//! appended under an exclusive file lock to `$CE_AUDIT_FILE` (else `~/.ce/audit/calls.jsonl`). Each row carries the previous row's
//! hash and its own: `hash = sha256(prev + "\n" + the row's JSON without hash)`, so an edited, inserted or removed row
//! breaks every hash after it. A deleted tail is caught by the signed heads the audit.log cell anchors in state.store.
//! Past [`MAX_BYTES`] the live file is sealed as `calls.<last seq>.jsonl` and the chain goes on in a new one; sealed
//! files are never deleted here ([`read_chain`] reads them all).
use ce_wire::CallRecord;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// The hash before the first row.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One row. `kind`: "call" (from [`file`]) or "event" (an app event through audit.log Append). For an event, `api` is
/// the app, `op` its op, `caller` the actor the app verified and `target` what it acted on.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Row {
    pub seq: u64,
    pub at_ms: u64,
    pub node: String,
    pub kind: String,
    pub api: String,
    pub op: String,
    pub right: String,
    pub caller: String,
    pub grant: String,
    pub target: String,
    pub ok: bool,
    pub detail: String,
    pub us: u64,
    pub prev: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hash: String,
}

impl Row {
    /// The hash this row must carry, from its own fields and `prev`.
    pub fn digest(&self) -> String {
        let mut r = self.clone();
        r.hash.clear();
        let body = serde_json::to_string(&r).unwrap_or_default();
        hex(&sha2::Sha256::digest(format!("{}\n{body}", self.prev).as_bytes()))
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn path() -> PathBuf {
    std::env::var_os("CE_AUDIT_FILE").map(Into::into).unwrap_or_else(|| ce_wire::ce_data_dir().join("audit/calls.jsonl"))
}

fn node() -> String {
    std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()).unwrap_or_default()
}

/// The last full line of the file (read from its tail).
fn last_line(f: &mut std::fs::File) -> std::io::Result<Option<String>> {
    let len = f.seek(SeekFrom::End(0))?;
    let mut back = 4096u64;
    loop {
        let start = len.saturating_sub(back);
        f.seek(SeekFrom::Start(start))?;
        let mut buf = String::new();
        f.read_to_string(&mut buf)?;
        let t = buf.trim_end_matches('\n');
        if let Some(i) = t.rfind('\n') {
            return Ok(Some(t[i + 1..].to_string()));
        }
        if start == 0 {
            return Ok((!t.is_empty()).then(|| t.to_string()));
        }
        back *= 4;
    }
}

/// Past this size the live file is sealed and the chain goes on in a new one; `$CE_AUDIT_MAX_BYTES` overrides it.
pub const MAX_BYTES: u64 = 64 << 20;

fn max_bytes() -> u64 {
    std::env::var("CE_AUDIT_MAX_BYTES").ok().and_then(|v| v.parse().ok()).unwrap_or(MAX_BYTES)
}

/// The sealed file for a chain whose last row is `seq`: `calls.jsonl` -> `calls.000000001234.jsonl`. The padding
/// makes name order seq order.
pub fn sealed_path(p: &Path, seq: u64) -> PathBuf {
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("calls");
    p.with_file_name(format!("{stem}.{seq:012}.jsonl"))
}

/// The sealed files of the chain at `p`, oldest first.
pub fn segments(p: &Path) -> Vec<PathBuf> {
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("calls").to_string();
    let Some(dir) = p.parent() else { return vec![] };
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|q| {
            let n = q.file_name().and_then(|n| n.to_str()).unwrap_or("");
            n.strip_prefix(&format!("{stem}.")).and_then(|r| r.strip_suffix(".jsonl")).is_some_and(|d| d.len() == 12 && d.bytes().all(|b| b.is_ascii_digit()))
        })
        .collect();
    v.sort();
    v
}

/// The whole chain at `p` as one text: every sealed file in order, then the live one (what [`verify_text`] walks).
pub fn read_chain(p: &Path) -> std::io::Result<String> {
    let mut out = String::new();
    for q in segments(p) {
        out.push_str(&std::fs::read_to_string(&q)?);
    }
    match std::fs::read_to_string(p) {
        Ok(t) => out.push_str(&t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    Ok(out)
}

/// Append `row` (seq, prev and hash are filled in here) to the chain at `p`; returns its seq. When the live file is
/// past [`MAX_BYTES`] it is sealed first (renamed under the lock); the new row continues the chain from its last row.
/// A writer that opened the file before another sealed it sees the inode change once it holds the lock and reopens.
pub fn append_at(p: &Path, row: Row) -> std::io::Result<u64> {
    append_capped(p, row, max_bytes())
}

/// True while `p` still names the file `f` has open. On unix a seal renames the live file away, so the inode tells; on
/// Windows an open file cannot be renamed, so a file we hold under the lock is still the live one.
#[cfg(unix)]
fn still_live(f: &std::fs::File, p: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let ino = f.metadata()?.ino();
    Ok(std::fs::metadata(p).map(|m| m.ino()).ok() == Some(ino))
}
#[cfg(not(unix))]
fn still_live(_f: &std::fs::File, _p: &Path) -> std::io::Result<bool> {
    Ok(true)
}

fn append_capped(p: &Path, mut row: Row, max: u64) -> std::io::Result<u64> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    for _ in 0..8 {
        let mut f = std::fs::OpenOptions::new().create(true).read(true).append(true).open(p)?;
        f.lock()?; // std file lock: flock on unix, LockFileEx on Windows
        let res = (|| {
            if !still_live(&f, p)? {
                return Ok(None); // sealed while we waited: open the new live file
            }
            let mut last: Option<Row> = last_line(&mut f)?.and_then(|l| serde_json::from_str(&l).ok());
            if f.metadata()?.len() >= max {
                if let Some(r) = &last {
                    std::fs::rename(p, sealed_path(p, r.seq))?;
                    let mut g = std::fs::OpenOptions::new().create_new(true).append(true).open(p)?;
                    return write_row(&mut g, &mut row, last.take()).map(Some);
                }
            }
            write_row(&mut f, &mut row, last).map(Some)
        })();
        let _ = f.unlock();
        if let Some(seq) = res? {
            return Ok(seq);
        }
    }
    Err(std::io::Error::other("audit file kept changing under the lock"))
}

fn write_row(f: &mut std::fs::File, row: &mut Row, last: Option<Row>) -> std::io::Result<u64> {
    row.seq = last.as_ref().map_or(1, |r| r.seq + 1);
    row.prev = last.map_or(GENESIS.to_string(), |r| r.hash);
    row.hash = row.digest();
    f.write_all(format!("{}\n", serde_json::to_string(&row).map_err(std::io::Error::other)?).as_bytes())?;
    Ok(row.seq)
}

pub fn append(row: Row) -> std::io::Result<u64> {
    append_at(&path(), row)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// A call as a row (seq, prev, hash still empty).
pub fn call_row(c: &CallRecord) -> Row {
    Row {
        at_ms: now_ms(),
        node: node(),
        kind: "call".into(),
        api: c.api.into(),
        op: c.op_name.into(),
        right: c.right.into(),
        caller: c.caller.clone(),
        grant: c.grant.clone(),
        ok: c.ok,
        detail: c.refusal.chars().take(300).collect(),
        us: c.us,
        ..Default::default()
    }
}

/// The observer for `Server::audit`: every answered call becomes a row in this node's chain. A write that fails is
/// said once on stderr per process and never fails the call.
pub fn file() -> impl Fn(&CallRecord) + Send + Sync + 'static {
    let warned = std::sync::atomic::AtomicBool::new(false);
    move |c: &CallRecord| {
        if let Err(e) = append(call_row(c)) {
            if !warned.swap(true, std::sync::atomic::Ordering::Relaxed) {
                eprintln!("audit: {}: {e}", path().display());
            }
        }
    }
}

/// What [`verify`] found. `first_bad`: the seq (or, for an unreadable line, line number) where the chain first breaks.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub rows: u64,
    pub first_bad: Option<u64>,
    pub why: String,
    pub head_seq: u64,
    pub head_hash: String,
}

/// Walk the chain: every line parses, its seq is one more than the last, its prev is the last hash and its hash is
/// its own digest. `anchor`: a signed head (seq, hash) from state.store that must still be in the file.
pub fn verify_text(text: &str, anchor: Option<(u64, &str)>) -> Report {
    let mut r = Report { head_hash: GENESIS.into(), ..Default::default() };
    let mut seen_anchor = anchor.is_none();
    for (i, l) in text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
        let bad = |r: &mut Report, at: u64, why: String| {
            r.first_bad = Some(at);
            r.why = why;
        };
        let row: Row = match serde_json::from_str(l) {
            Ok(x) => x,
            Err(e) => {
                bad(&mut r, i as u64 + 1, format!("line {} is not a row: {e}", i + 1));
                return r;
            }
        };
        let want = r.head_seq + 1;
        if row.seq != want {
            bad(&mut r, row.seq, format!("seq {} where {want} was next", row.seq));
            return r;
        }
        if row.prev != r.head_hash {
            let why = format!("seq {}: prev is not the hash of seq {}", row.seq, r.head_seq);
            bad(&mut r, row.seq, why);
            return r;
        }
        if row.digest() != row.hash {
            bad(&mut r, row.seq, format!("seq {}: the row was changed after it was written", row.seq));
            return r;
        }
        if let Some((s, h)) = anchor {
            if row.seq == s {
                if row.hash != h {
                    bad(&mut r, s, format!("seq {s} differs from the signed head"));
                    return r;
                }
                seen_anchor = true;
            }
        }
        r.rows += 1;
        r.head_seq = row.seq;
        r.head_hash = row.hash;
    }
    if !seen_anchor {
        let (s, _) = anchor.unwrap();
        r.first_bad = Some(r.head_seq + 1);
        r.why = format!("the signed head is seq {s} but the file ends at seq {}: rows were removed", r.head_seq);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(op: &'static str) -> CallRecord {
        CallRecord { api: "t.x", op: 2, op_name: op, right: "t.x:read", caller: "ab".into(), grant: "g1".into(), ok: true, refusal: String::new(), us: 5 }
    }

    #[test]
    fn chain_catches_an_edit_and_a_cut() {
        let p = std::env::temp_dir().join(format!("ce-audit-{}.jsonl", std::process::id()));
        std::fs::remove_file(&p).ok();
        for op in ["A", "B", "C"] {
            append_at(&p, call_row(&rec(op))).unwrap();
        }
        let text = std::fs::read_to_string(&p).unwrap();
        let good = verify_text(&text, None);
        assert_eq!((good.rows, good.first_bad, good.head_seq), (3, None, 3));
        // one changed letter in row 2
        let edited = text.replacen("\"op\":\"B\"", "\"op\":\"Z\"", 1);
        assert_eq!(verify_text(&edited, None).first_bad, Some(2));
        // row 2 removed: row 3's prev no longer matches
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(verify_text(&format!("{}\n{}\n", lines[0], lines[2]), None).first_bad, Some(3));
        // the tail cut: the chain is fine, the anchor catches it
        let cut = format!("{}\n{}\n", lines[0], lines[1]);
        assert_eq!(verify_text(&cut, None).first_bad, None);
        assert_eq!(verify_text(&cut, Some((3, &good.head_hash))).first_bad, Some(3));
        assert_eq!(verify_text(&text, Some((3, &good.head_hash))).first_bad, None);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn a_sealed_file_continues_the_chain() {
        let dir = std::env::temp_dir().join(format!("ce-audit-rot-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let p = dir.join("calls.jsonl");
        for op in ["A", "B", "C", "D", "E", "F", "G"] {
            append_capped(&p, call_row(&rec(op)), 600).unwrap(); // about two rows per file
        }
        let segs = segments(&p);
        assert!(segs.len() >= 2, "sealed {segs:?}");
        let text = read_chain(&p).unwrap();
        let r = verify_text(&text, None);
        assert_eq!((r.rows, r.first_bad, r.head_seq), (7, None, 7));
        // the live file starts where the last sealed one ended
        let first_live: Row = serde_json::from_str(std::fs::read_to_string(&p).unwrap().lines().next().unwrap()).unwrap();
        let last_sealed: Row = serde_json::from_str(std::fs::read_to_string(segs.last().unwrap()).unwrap().lines().last().unwrap()).unwrap();
        assert_eq!((first_live.seq, first_live.prev), (last_sealed.seq + 1, last_sealed.hash));
        // a sealed file removed breaks the chain where it was
        std::fs::remove_file(&segs[0]).unwrap();
        assert!(verify_text(&read_chain(&p).unwrap(), None).first_bad.is_some());
        std::fs::remove_dir_all(&dir).ok();
    }
}
