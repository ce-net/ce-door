//! `door-stranger-check serve`: the door.stranger-check cell behind this machine's door, gated by ce-cap (default deny).
//! `door-stranger-check check [--no-control] <host:port> <api>...`: the same check from a shell; exit 0 PASS, 1 OPEN,
//! 2 INCONCLUSIVE, 3 bad input.
use ce_wire::Server;
use door_stranger_check_api::*;
use std::time::Instant;

async fn serve() -> Result<(), String> {
    let me = ce_gate::node_identity().map_err(|e| e.to_string())?;
    let started = Instant::now();
    let gate = ce_gate::Gate::<DoorStrangerCheck>::new(me.node_id(), ce_gate::mesh_roots()).into_fn();
    Server::<DoorStrangerCheck>::new(gate)
        .on::<HealthOp, _, _>(move |_: (), _| async move { Ok(Health { ok: true, version: env!("CARGO_PKG_VERSION").into(), uptime_s: started.elapsed().as_secs() }) })
        .on::<Check, _, _>(|r: CheckReq, _| async move {
            Ok(tokio::task::spawn_blocking(move || door_stranger_check::check(r)).await.unwrap_or_else(|e| Err(CheckError::Invalid(e.to_string()))))
        })
        .serve_door()
        .await
        .map_err(|e| e.to_string())
}

fn cli(args: &[String]) -> i32 {
    let control = !args.iter().any(|a| a == "--no-control");
    let rest: Vec<String> = args.iter().filter(|a| !a.starts_with("--")).cloned().collect();
    let Some((addr, apis)) = rest.split_first() else {
        eprintln!("usage: door-stranger-check check [--no-control] <host:port> <api>...");
        return 3;
    };
    match door_stranger_check::check(CheckReq { addr: addr.clone(), apis: apis.to_vec(), control }) {
        Ok(rep) => {
            print!("{}", door_stranger_check::render(&rep));
            match rep.verdict.as_str() { "PASS" => 0, "OPEN" => 1, _ => 2 }
        }
        Err(e) => {
            eprintln!("door-stranger-check: {e:?}");
            3
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match args.get(1).map(String::as_str) {
        Some("serve") => match tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(serve()) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("door-stranger-check: {e}");
                1
            }
        },
        Some("check") => cli(&args[2..]),
        _ => {
            eprintln!("usage: door-stranger-check serve | check [--no-control] <host:port> <api>...");
            3
        }
    };
    std::process::exit(code);
}
