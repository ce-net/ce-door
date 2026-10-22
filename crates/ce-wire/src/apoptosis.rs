//! A cell's typed dying routine : cells die and get replaced all the time, so every
//! cell has a persistent, typed dying routine that saves everything before it stops and answers at once when it is
//! requested again.
//!
//! It is not an op of the cell's api: an op would change every cell's schema hash and refuse every caller built
//! before it. It travels on the door's registration socket, which only the door and the cell share:
//! - cell -> door, on REGISTER: `apo=<ms>`, the time its routine may take (a door that does not know it ignores it);
//! - door -> cell, before any stop: `u32 LE (APO_MARK | len)` + postcard [`ApoptosisReq`], no fd (a handoff's len is
//!   at most 64 KiB, so the mark never collides; a door sends it only to a cell that said `apo=`);
//! - cell -> door: `u32 LE len` + postcard `Result<Saved, String>`. Then the door closes the registration as before.
//!
//! A cell without a routine answers `Saved::default()` at once; a cell built before this never says `apo=` and is
//! stopped exactly as before. The tokio server also runs the routine on SIGTERM when the cell set one.
use serde::{Deserialize, Serialize};

/// The high bit of the length word marks a door -> cell control message (no fd).
pub const APO_MARK: u32 = 1 << 31;
/// The time a routine gets when the cell does not say (`apo=` on REGISTER): 2 s.
pub const APOPTOSIS_MS: u32 = 2_000;
/// The most a cell may ask for: a stop never waits longer than this per cell.
pub const APOPTOSIS_MAX_MS: u32 = 30_000;

/// The door is about to stop this process: save what must survive, within `deadline_ms`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ApoptosisReq {
    /// Why: "idle 900 s", "stop", "restart", "update", "stop-owner <owner>: <why>", "SIGTERM".
    pub reason: String,
    pub deadline_ms: u32,
}

/// What the routine saved: bytes written and where (a state.store key, a file). Zero and empty: nothing to save.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Saved {
    pub bytes: u64,
    pub at: String,
}

/// One framed message: `u32 LE (mark | len)` + postcard body.
pub fn apo_frame<T: Serialize>(mark: u32, v: &T) -> Vec<u8> {
    let body = postcard::to_stdvec(v).unwrap_or_default();
    let mut b = ((body.len() as u32) | mark).to_le_bytes().to_vec();
    b.extend_from_slice(&body);
    b
}

/// ` apo=<ms>` for a REGISTER line.
pub fn apo_field(ms: u32) -> String {
    format!(" apo={}", ms.clamp(1, APOPTOSIS_MAX_MS))
}

/// Split complete `u32 LE len | body` frames off the front of `buf` (cell -> door answers), leaving a partial one.
pub fn take_frames(buf: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        if buf.len() < 4 {
            return out;
        }
        let len = (u32::from_le_bytes(buf[..4].try_into().unwrap()) & !APO_MARK) as usize;
        if len > 64 * 1024 {
            // not a frame (a cell writing garbage): drop it all rather than grow without end
            buf.clear();
            return out;
        }
        if buf.len() < 4 + len {
            return out;
        }
        out.push(buf[4..4 + len].to_vec());
        buf.drain(..4 + len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_roundtrip_and_split() {
        let r = ApoptosisReq { reason: "idle 900 s".into(), deadline_ms: 2000 };
        let f = apo_frame(APO_MARK, &r);
        assert_ne!(u32::from_le_bytes(f[..4].try_into().unwrap()) & APO_MARK, 0);
        let ok: Result<Saved, String> = Ok(Saved { bytes: 42, at: "state.store:x/y".into() });
        let mut buf = f.clone();
        buf.extend(apo_frame(0, &ok));
        buf.extend_from_slice(&[5, 0]);
        let fr = take_frames(&mut buf);
        assert_eq!(fr.len(), 2);
        assert_eq!(postcard::from_bytes::<ApoptosisReq>(&fr[0]).unwrap(), r);
        assert_eq!(postcard::from_bytes::<Result<Saved, String>>(&fr[1]).unwrap(), ok);
        assert_eq!(buf, [5, 0], "a partial frame stays");
        assert_eq!(apo_field(0), " apo=1");
        assert_eq!(apo_field(99_999), " apo=30000");
    }
}
