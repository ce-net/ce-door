//! api.lock (`ce_wire::check_lock`): written when missing, kept when an op is added, refused when an op changes or
//! goes at the same version, moved on after a freeze.
mod v1 {
    ce_wire::api! {
        api A = "lock.test", version 1;
        types { pub struct R { pub a: u32 } }
        ops { 1 => One(R) -> u32, needs "lock.test:r"; 2 => Two(()) -> String, needs "lock.test:r"; }
    }
}
mod added {
    ce_wire::api! {
        api A = "lock.test", version 1;
        types { pub struct R { pub a: u32 } }
        ops { 1 => One(R) -> u32, needs "lock.test:r"; 2 => Two(()) -> String, needs "lock.test:r"; 3 => Three(()) -> (), needs "lock.test:r"; }
    }
}
mod changed {
    ce_wire::api! {
        api A = "lock.test", version 1;
        types { pub struct R { pub a: u32, pub b: bool } }
        ops { 1 => One(R) -> u32, needs "lock.test:r"; }
    }
}
mod v2 {
    ce_wire::api! {
        api A = "lock.test", version 2;
        types { pub struct R { pub a: u32, pub b: bool } }
        ops { 1 => One(R) -> u32, needs "lock.test:r"; }
    }
}

#[test]
fn lock_follows_the_rules() {
    let d = std::env::temp_dir().join(format!("ce-wire-lock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let lock = d.join("api.lock");
    assert!(ce_wire::check_lock::<v1::A>(&lock).unwrap().contains("written"));
    assert!(ce_wire::check_lock::<v1::A>(&lock).unwrap().contains("unchanged"));
    assert!(ce_wire::check_lock::<added::A>(&lock).unwrap().contains("added Three"));
    let e = ce_wire::check_lock::<changed::A>(&lock).unwrap_err();
    assert!(e.contains("op One (#1) changed shape") && e.contains("op Two (#2) removed") && e.contains("ce-wire-gen freeze"), "{e}");
    let e = ce_wire::check_lock::<v2::A>(&lock).unwrap_err();
    assert!(e.contains("src/versions/v1.rs is missing"), "{e}");
    std::fs::create_dir_all(d.join("src/versions")).unwrap();
    std::fs::write(d.join("src/versions/v1.rs"), "// frozen").unwrap();
    assert!(ce_wire::check_lock::<v2::A>(&lock).unwrap().contains("lock now v2"));
    assert!(ce_wire::check_lock::<v1::A>(&lock).unwrap_err().contains("went back"));
    std::fs::remove_dir_all(&d).unwrap();
}
