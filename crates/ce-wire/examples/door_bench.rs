//! Door bench: connect + first call, direct vs through the door (fd handoff), then call latency on a handed-over
//! connection. `cargo run --release --example door_bench -- [connects] [calls]`
use ce_wire::{Caller, Client, Server};
use std::time::{Duration, Instant};

mod echo {
    ce_wire::api! {
        api EchoApi = "bench.door", version 1;
        types { pub struct Ping { pub seq: u64 } }
        ops { 1 => Echo(Ping) -> Ping, needs "bench.echo"; }
    }
}
use echo::*;

fn srv() -> Server<EchoApi> {
    Server::<EchoApi>::new(|_| Ok(Caller { name: "bench".into(), rights: vec!["bench.echo".into()] }))
        .on::<Echo, _, _>(|p: Ping, _| async move { Ok(p) })
}

fn pct(mut v: Vec<f64>) -> (f64, f64) {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (v[v.len() / 2], v[v.len() * 99 / 100])
}

fn main() {
    let a: Vec<usize> = std::env::args().skip(1).filter_map(|s| s.parse().ok()).collect();
    let (nc, ncall) = (*a.first().unwrap_or(&2000), *a.get(1).unwrap_or(&20000));
    let dir = std::env::temp_dir().join(format!("ce-door-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::env::set_var("CE_DOOR_SOCK", dir.join("door.sock"));
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async move {
        let direct = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let daddr = direct.local_addr().unwrap();
        tokio::spawn(srv().serve(direct));
        let door: std::net::SocketAddr = { std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap() };
        tokio::spawn(ce_wire::run_door(vec![door], dir.join("door.sock")));
        tokio::time::sleep(Duration::from_millis(50)).await;
        tokio::spawn(srv().serve_door());
        tokio::time::sleep(Duration::from_millis(50)).await;

        for (mode, addr) in [("direct", daddr), ("door", door), ("direct", daddr), ("door", door)] {
            let mut ts = Vec::with_capacity(nc);
            for i in 0..nc {
                let t = Instant::now();
                let c = Client::<EchoApi>::connect_opts(addr, vec![], false, Duration::from_secs(1)).await.unwrap();
                c.call::<Echo>(&Ping { seq: i as u64 }).await.unwrap();
                ts.push(t.elapsed().as_secs_f64() * 1e3);
            }
            let (p50, p99) = pct(ts);
            println!("{{\"mode\":\"connect+call {mode}\",\"n\":{nc},\"p50_ms\":{p50:.4},\"p99_ms\":{p99:.4}}}");
        }
        for (mode, addr) in [("direct", daddr), ("door", door)] {
            let c = Client::<EchoApi>::connect_opts(addr, vec![], false, Duration::from_secs(1)).await.unwrap();
            for i in 0..1000 { c.call::<Echo>(&Ping { seq: i }).await.unwrap(); }
            let mut ts = Vec::with_capacity(ncall);
            for i in 0..ncall {
                let t = Instant::now();
                c.call::<Echo>(&Ping { seq: i as u64 }).await.unwrap();
                ts.push(t.elapsed().as_secs_f64() * 1e3);
            }
            let (p50, p99) = pct(ts);
            println!("{{\"mode\":\"call after connect {mode}\",\"n\":{ncall},\"p50_ms\":{p50:.4},\"p99_ms\":{p99:.4}}}");
        }
    });
}
