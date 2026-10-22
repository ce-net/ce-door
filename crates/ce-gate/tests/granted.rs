//! CE_AS + CE_GRANT: a boxed principal calls with its own key and the grant in its wallet, never the machine's key.
use ce_cap::{Caveats, Resource, SignedCapability};
use ce_identity::Identity;

#[test]
fn wallet_cap_reads_one_entry() {
    let w = "[entries.\"ops:a\"]\nnode_id = \"11\"\ncap = \"aa01\"\n\n[entries.\"ops:b\"]\nnode_id = \"22\"\ncap = \"bb02\"\n";
    assert_eq!(ce_gate::wallet_cap(w, "ops:b").as_deref(), Some("bb02"));
    assert_eq!(ce_gate::wallet_cap(w, "ops:a").as_deref(), Some("aa01"));
    assert_eq!(ce_gate::wallet_cap(w, "ops:c"), None);
    assert_eq!(ce_gate::wallet_cap("[entries.\"ops:a\"]\ncap = \"\"\n", "ops:a"), None);
}

// One test touches the process env (CE_AS/CE_GRANT), so everything env-dependent stays in it.
#[test]
fn granted_uses_the_lane_key_and_wallet_grant_or_fails_closed() {
    assert!(std::env::var_os("CE_AS").is_none());
    assert!(ce_gate::granted().unwrap().is_none(), "unset: the node's own key as before");

    let dir = std::env::temp_dir().join(format!("ce-gate-granted-{}", std::process::id()));
    let principal = Identity::load_or_generate(&dir.join("identity")).unwrap();
    let root = Identity::from_secret_bytes(&[9u8; 32]);
    let chain = vec![SignedCapability::issue(&root, principal.node_id(), vec!["x.y:read".into()], Resource::Any, Caveats::default(), 7, None)];
    std::fs::write(dir.join("wallet.toml"), format!("[entries.\"ops:t\"]\nnode_id = \"{}\"\ncap = \"{}\"\n", root.node_id_hex(), ce_cap::encode_chain(&chain))).unwrap();

    std::env::set_var("CE_AS", &dir);
    std::env::set_var("CE_GRANT", "ops:t");
    let (id, got) = ce_gate::granted().unwrap().expect("a grant");
    assert_eq!(id.node_id(), principal.node_id());
    assert_eq!(ce_cap::encode_chain(&got), ce_cap::encode_chain(&chain));

    // a named grant that is not there, or no key, is an error: never a fall back to the machine's key
    std::env::set_var("CE_GRANT", "ops:missing");
    assert!(ce_gate::granted().is_err());
    std::env::set_var("CE_AS", dir.join("nowhere"));
    std::env::set_var("CE_GRANT", "ops:t");
    assert!(ce_gate::granted().is_err());
    std::env::remove_var("CE_AS");
    std::env::remove_var("CE_GRANT");
    std::fs::remove_dir_all(&dir).unwrap();
}
