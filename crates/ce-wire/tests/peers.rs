//! `$CE_WIRE_PEERS` / the peers file: an ip, or ip:port with the port ignored; anything else is skipped and said.

#[test]
fn peers_take_ip_and_ip_port() {
    std::env::set_var("CE_WIRE_PEERS", "100.64.12.3:7700,10.0.1.5 ab12,not-a-host");
    let v = ce_wire::mesh_peer_ids();
    std::env::remove_var("CE_WIRE_PEERS");
    assert_eq!(v.iter().map(|(ip, _)| ip.to_string()).collect::<Vec<_>>(), ["100.64.12.3", "10.0.1.5"]);
    assert_eq!(v[1].1.as_deref(), Some("ab12"));
}
