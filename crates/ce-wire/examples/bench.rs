//! Loopback bench: typed call latency and throughput. `cargo run --release --example bench -- [n] [concurrency]`
use ce_wire::{Caller, Client, Server};
use std::time::Instant;

mod echo {
    ce_wire::api! {
        api EchoApi = "bench.echo", version 1;
        types { pub struct Ping { pub seq: u64, pub pad: Vec<u8> } }
        ops { 1 => Echo(Ping) -> Ping, needs "bench.echo"; }
    }
}
use echo::*;

fn main() {
    let a: Vec<usize> = std::env::args().skip(1).filter_map(|s| s.parse().ok()).collect();
    let (n, conc) = (*a.first().unwrap_or(&20000), *a.get(1).unwrap_or(&64));
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async move {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let srv = Server::<EchoApi>::new(|_| Ok(Caller { name: "bench".into(), rights: vec!["bench.echo".into()] }))
            .on::<Echo, _, _>(|p: Ping, _| async move { Ok(p) });
        tokio::spawn(srv.serve(l));
        let c = std::rc::Rc::new(Client::<EchoApi>::connect(addr, vec![]).await.unwrap());
        let ping = Ping { seq: 0, pad: vec![b'x'; 64] };
        for _ in 0..1000 { c.call::<Echo>(&ping).await.unwrap(); }
        let mut ts = Vec::with_capacity(n);
        let t0 = Instant::now();
        for i in 0..n {
            let t = Instant::now();
            let r = c.call::<Echo>(&Ping { seq: i as u64, pad: ping.pad.clone() }).await.unwrap();
            assert_eq!(r.seq, i as u64);
            ts.push(t.elapsed().as_secs_f64() * 1e3);
        }
        let el = t0.elapsed().as_secs_f64();
        ts.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!("{{\"mode\":\"sequential\",\"n\":{n},\"p50_ms\":{:.4},\"p99_ms\":{:.4},\"rps\":{:.0}}}", ts[n / 2], ts[n * 99 / 100], n as f64 / el);
        let local = tokio::task::LocalSet::new();
        let t0 = Instant::now();
        local.run_until(async {
            let mut hs = Vec::new();
            for _ in 0..conc {
                let (c, pad) = (c.clone(), ping.pad.clone());
                hs.push(tokio::task::spawn_local(async move {
                    for i in 0..n / conc { c.call::<Echo>(&Ping { seq: i as u64, pad: pad.clone() }).await.unwrap(); }
                }));
            }
            for h in hs { h.await.unwrap(); }
        }).await;
        let el = t0.elapsed().as_secs_f64();
        println!("{{\"mode\":\"pipelined\",\"concurrency\":{conc},\"n\":{},\"rps\":{:.0}}}", n / conc * conc, (n / conc * conc) as f64 / el);
    });
}
