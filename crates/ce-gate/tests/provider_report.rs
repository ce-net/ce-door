//! Provider proof in report mode (`CE_PROVIDER_PROOF=report`): a provider without a
//! good proof is logged and the call goes through, except for the apis listed strict. Its own test binary: the
//! verifier hook and the ce data dir are per process.
use ce_gate::provider::{self, Mode};
use ce_wire::{blocking, Refusal, WireError};

mod r {
    ce_wire::api! {
        api R = "example.test.report", version 1;
        types { pub struct K { pub k: u8 } }
        ops { 1 => Get(K) -> K, needs "r:get"; }
    }
}
use r::*;

#[test]
fn modes_refuse_what_they_list() {
    assert!(Mode::Strict.refuses("anything"));
    let m = Mode::Report { strict: vec!["keys".into(), "cell.install".into(), "storage.*".into()] };
    for a in ["keys", "cell.install", "storage", "storage.r2", "storage.r2.eu"] {
        assert!(m.refuses(a), "{a}");
    }
    for a in ["keys2", "keys.read", "cell", "cell.installer", "storagex", "docs.read"] {
        assert!(!m.refuses(a), "{a}");
    }
}

#[test]
fn report_logs_and_lets_through_strict_refuses() {
    let dir = std::env::temp_dir().join(format!("ce-provider-report-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::env::set_var("CE_DATA_DIR", &dir);
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    let s = blocking::Server::<R>::new(|_h: &ce_wire::Hello| Ok(ce_wire::Caller { name: "t".into(), rights: vec!["*".into()] })).on::<Get, _>(|k: K, _| Ok(k));
    std::thread::spawn(move || s.serve(l));

    // report: no serve proof, the call works, one line in the log
    provider::enable_verifier_mode(Mode::Report { strict: vec![] }).unwrap();
    let c = blocking::Client::<R>::connect(a, vec![]).unwrap();
    assert_eq!(c.call::<Get>(&K { k: 3 }).unwrap(), K { k: 3 });
    let log = std::fs::read_to_string(dir.join("provider-proof.log")).unwrap();
    assert!(log.contains(" would-refuse example.test.report 127.0.0.1 n=1 ") && log.contains("no serve proof"), "{log}");
    // a second check within the hour is counted, not logged
    blocking::Client::<R>::connect(a, vec![]).unwrap();
    assert_eq!(std::fs::read_to_string(dir.join("provider-proof.log")).unwrap(), log);

    // report with this api listed strict: refused as in strict mode
    provider::enable_verifier_mode(Mode::Report { strict: vec!["example.test.*".into()] }).unwrap();
    match blocking::Client::<R>::connect(a, vec![]) {
        Err(WireError::Refused(Refusal::Gate(e))) => assert!(e.contains("no serve proof"), "{e}"),
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("accepted a provider its strict list names"),
    }
    let log2 = std::fs::read_to_string(dir.join("provider-proof.log")).unwrap();
    assert!(log2.strip_prefix(&log).is_some_and(|l| l.contains(" refused example.test.report 127.0.0.1 n=1 ")), "{log2}");

    // a provider with a serve chain (rooted at this node, a serve root of its own) is logged ok
    let me = ce_gate::node_identity().unwrap();
    let cv = ce_gate::ce_cap::Caveats { not_before: 0, not_after: u64::MAX / 2, ..Default::default() };
    let chain = vec![provider::serve_cap(&me, me.node_id(), "example.test.report", <R as ce_wire::Api>::SCHEMA, None, cv)];
    provider::enable_prover(ce_gate::node_identity().unwrap(), vec![chain], None);
    provider::enable_verifier_mode(Mode::Report { strict: vec![] }).unwrap();
    let c = blocking::Client::<R>::connect(a, vec![]).unwrap();
    assert_eq!(c.call::<Get>(&K { k: 4 }).unwrap(), K { k: 4 });
    let log3 = std::fs::read_to_string(dir.join("provider-proof.log")).unwrap();
    assert!(log3.strip_prefix(&log2).is_some_and(|l| l.contains(" ok example.test.report 127.0.0.1 n=1 ")), "{log3}");
    ce_wire::provider::clear();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn node_file_parses() {
    assert_eq!(Mode::parse("report keys,cell.install,storage.*\n"), Some(Mode::Report { strict: vec!["keys".into(), "cell.install".into(), "storage.*".into()] }));
    assert_eq!(Mode::parse("# rollout note\nreport\n"), Some(Mode::Report { strict: vec![] }));
    assert_eq!(Mode::parse("report keys, cell.install"), Some(Mode::Report { strict: vec!["keys".into(), "cell.install".into()] }));
    assert_eq!(Mode::parse("strict"), Some(Mode::Strict));
    assert_eq!(Mode::parse("off"), None);
    assert_eq!(Mode::parse(""), None);
}
