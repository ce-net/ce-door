//! What the gate costs a call: the same blocking cell behind `Gate` (a signed Hello, a ce-cap chain rooted at the
//! cell, rights from its abilities) and behind an open door that admits everyone, on loopback.
//! `cargo run --release -p ce-gate --example gate_bench -- [connects] [calls]`
//! Prints p50/p99 for connect + first call (where the gate checks the chain) and for a call on an open connection
//! (where it checks the op's right against the rights it granted at Hello).
use ce_cap::{Caveats, Resource, SignedCapability};
use ce_gate::{proof, Gate};
use ce_identity::Identity;
use ce_wire::{blocking, Api, Caller};
use std::time::Instant;

mod echo {
    ce_wire::api! {
        api Echo = "bench.gate", version 1;
        types { pub struct Ping { pub seq: u64 } }
        ops { 1 => Call(Ping) -> Ping, needs "bench.gate:call"; }
    }
}
use echo::*;

fn pct(mut v: Vec<f64>) -> (f64, f64) {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (v[v.len() / 2], v[v.len() * 99 / 100])
}

fn serve(gated: bool, cell: &Identity) -> std::net::SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    let s = if gated {
        blocking::Server::<Echo>::new(Gate::<Echo>::new(cell.node_id(), vec![]).into_fn())
    } else {
        blocking::Server::<Echo>::new(|_: &ce_wire::Hello| Ok(Caller { name: "anyone".into(), rights: vec!["bench.gate:call".into()] }))
    };
    let s = s.on::<Call, _>(|p: Ping, _| Ok(p));
    std::thread::spawn(move || s.serve(l));
    a
}

fn main() {
    let a: Vec<usize> = std::env::args().skip(1).filter_map(|s| s.parse().ok()).collect();
    let (nc, ncall) = (*a.first().unwrap_or(&2000), *a.get(1).unwrap_or(&20000));
    std::env::set_var("CE_DATA_DIR", std::env::temp_dir().join(format!("ce-gate-bench-{}", std::process::id())));
    let cell = Identity::from_secret_bytes(&[1; 32]);
    let alice = Identity::from_secret_bytes(&[2; 32]);
    let chain = vec![SignedCapability::issue(&cell, alice.node_id(), vec!["bench.gate:*".into()], Resource::Any, Caveats::default(), 7, None)];
    println!("connects={nc} calls={ncall} (loopback, one machine, blocking client and server)");
    // the gate's own work at a Hello, in process: the caller signs a proof, the gate checks it
    let gate = Gate::<Echo>::new(cell.node_id(), vec![]).into_fn();
    let (mut sign, mut check) = (Vec::with_capacity(nc), Vec::with_capacity(nc));
    for _ in 0..nc {
        let t = Instant::now();
        let token = proof::<Echo>(&alice, &chain);
        sign.push(t.elapsed().as_secs_f64() * 1e6);
        let h = ce_wire::Hello { api: Echo::NAME.into(), version: Echo::VERSION, schema: Echo::SCHEMA, token, spawn: false };
        let t = Instant::now();
        gate(&h).unwrap();
        check.push(t.elapsed().as_secs_f64() * 1e6);
    }
    let ((s50, s99), (c50, c99)) = (pct(sign), pct(check));
    println!("hello caller signs a proof p50 {s50:6.1} us  p99 {s99:6.1} us | gate checks it p50 {c50:6.1} us  p99 {c99:6.1} us");
    for gated in [false, true] {
        let addr = serve(gated, &cell);
        // every connect presents a fresh proof (a gate refuses a replayed Hello); signing it is part of the cost
        let tok = || if gated { proof::<Echo>(&alice, &chain) } else { Vec::new() };
        let mut first = Vec::with_capacity(nc);
        for i in 0..nc {
            let t = Instant::now();
            let c = blocking::Client::<Echo>::connect(addr, tok()).unwrap();
            c.call::<Call>(&Ping { seq: i as u64 }).unwrap();
            first.push(t.elapsed().as_secs_f64() * 1e6);
        }
        let c = blocking::Client::<Echo>::connect(addr, tok()).unwrap();
        for i in 0..1000 { c.call::<Call>(&Ping { seq: i }).unwrap(); }
        let mut per = Vec::with_capacity(ncall);
        for i in 0..ncall {
            let t = Instant::now();
            c.call::<Call>(&Ping { seq: i as u64 }).unwrap();
            per.push(t.elapsed().as_secs_f64() * 1e6);
        }
        let ((f50, f99), (p50, p99)) = (pct(first), pct(per));
        println!("{:<5} connect+first call p50 {f50:7.1} us  p99 {f99:7.1} us | call on open connection p50 {p50:6.1} us  p99 {p99:6.1} us",
            if gated { "gate" } else { "open" });
    }
}
