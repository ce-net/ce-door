//! `api.lock`: the per-op hashes callers of this version rely on, committed next to the api crate and checked by
//! `cargo test`. It runs where the tests run, offline and in a container, so an api
//! change that would refuse old callers fails before it ships. `ce-wire-gen check` is the same rule over git.
use crate::Api;
use std::path::Path;

/// Check `A` against the lock at `lock` (usually `<crate>/api.lock`) and bring the lock up to date when nothing breaks:
/// missing, it is written; same version, every locked op must keep its id and per-op hash (new ops are added);
/// a higher version needs `<crate>/src/versions/v<locked>.rs` (`ce-wire-gen freeze`), then the lock moves to it.
/// Ok says what changed; Err names each op that would refuse callers and the fix.
pub fn check_lock<A: Api>(lock: &Path) -> Result<String, String> {
    let cur: Vec<(u32, &str, u64)> = A::OPS.iter().map(|o| (o.id, o.name, crate::shape_hash(A::NAME, A::TYPES, o))).collect();
    let write = |what: String| -> Result<String, String> {
        let mut t = format!("# {}: the per-op hashes callers of this version rely on. Kept by ce_wire::check_lock in cargo test; commit it.\nversion {}\n", A::NAME, A::VERSION);
        for (id, name, h) in &cur {
            t.push_str(&format!("{id} {name} {h:016x}\n"));
        }
        std::fs::write(lock, t).map_err(|e| format!("{}: {e}", lock.display()))?;
        Ok(what)
    };
    let text = match std::fs::read_to_string(lock) {
        Ok(t) => t,
        Err(_) => return write(format!("{} written for {} v{}: commit it", lock.display(), A::NAME, A::VERSION)),
    };
    let mut ver = None;
    let mut locked: Vec<(u32, String, u64)> = vec![];
    for l in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let w: Vec<&str> = l.split_whitespace().collect();
        match w.as_slice() {
            ["version", v] => ver = v.parse::<u32>().ok(),
            [id, name, h] => locked.push((id.parse().map_err(|_| format!("{}: bad line {l:?}", lock.display()))?, name.to_string(), u64::from_str_radix(h, 16).map_err(|_| format!("{}: bad line {l:?}", lock.display()))?)),
            _ => return Err(format!("{}: bad line {l:?}", lock.display())),
        }
    }
    let lv = ver.ok_or_else(|| format!("{}: no `version N` line", lock.display()))?;
    let fix = format!("fix: put the v{lv} api back, `ce-wire-gen freeze src/lib.rs` (keeps v{lv} in src/versions/, live block becomes v{}), make the change there, `ce-wire-gen adapt src/lib.rs --from src/versions/v{lv}.rs`", lv + 1);
    if A::VERSION < lv {
        return Err(format!("{} went back from v{lv} to v{}\n{fix}", A::NAME, A::VERSION));
    }
    if A::VERSION > lv {
        let kept = lock.parent().unwrap_or(Path::new(".")).join(format!("src/versions/v{lv}.rs"));
        if !kept.is_file() {
            return Err(format!("{} is at v{} but {} is missing: callers at v{lv} lose their adapter\n{fix}", A::NAME, A::VERSION, kept.display()));
        }
        return write(format!("{} v{lv} kept in {}; lock now v{}: commit it", A::NAME, kept.display(), A::VERSION));
    }
    let mut broken = vec![];
    for (id, name, h) in &locked {
        match cur.iter().find(|c| c.0 == *id) {
            None => broken.push(format!("op {name} (#{id}) removed")),
            Some((_, n, ch)) if ch != h => broken.push(format!("op {n} (#{id}) changed shape")),
            Some(_) => {}
        }
    }
    if !broken.is_empty() {
        return Err(format!("{} v{}: {}: callers at v{lv} would be refused\n{fix}", A::NAME, A::VERSION, broken.join("; ")));
    }
    let added: Vec<&str> = cur.iter().filter(|c| !locked.iter().any(|l| l.0 == c.0)).map(|c| c.1).collect();
    if added.is_empty() {
        return Ok(format!("{} v{}: every locked op unchanged", A::NAME, A::VERSION));
    }
    write(format!("{} v{}: added {}: lock updated, commit it", A::NAME, A::VERSION, added.join(", ")))
}
