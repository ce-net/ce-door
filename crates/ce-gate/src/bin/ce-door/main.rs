//! ce-door: this machine's one ce-wire door. The door is a unix socket that hands accepted connections to cells with
//! SCM_RIGHTS (`unix.rs`). Windows has neither, so its door (a named pipe + WSADuplicateSocket) is a separate design,
//! not built yet. Until then a Windows node runs `ce` and calls cells; it hosts none.
#[cfg(unix)]
mod unix;

#[cfg(unix)]
fn main() {
    unix::main()
}

#[cfg(not(unix))]
fn main() {
    eprintln!("ce-door: no door on this OS yet; this node can call cells but not host them");
    std::process::exit(2);
}
